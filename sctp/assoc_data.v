module sctp

import time

// Sending and receiving user data: fragmentation, acknowledgement,
// retransmission, congestion control and reassembly.

// fast_retransmit_threshold is how many acknowledgements must report a TSN
// missing before it is resent without waiting for the timer
// (RFC 4960 section 7.2.4). Three is the value TCP uses and for the same
// reason: fewer would make reordering look like loss.
const fast_retransmit_threshold = 3

// send queues a message for delivery on a stream.
//
// A message larger than one packet is fragmented; the peer reassembles it and
// the application sees one message. It is refused rather than truncated when it
// exceeds the negotiated maximum, because a receiver that has advertised a
// limit will drop what exceeds it.
pub fn (mut a Association) send(stream_identifier u16, payload_protocol_identifier u32, data []u8, ordered bool) ! {
	a.mu.lock()
	defer {
		a.mu.unlock()
	}

	if a.closed || a.state == .aborted {
		return AssociationError{
			reason: .closed
			detail: if a.abort_reason != '' { a.abort_reason } else { 'the association is closed' }
		}
	}
	if a.state != .established {
		return AssociationError{
			reason: .wrong_state
			detail: 'the association is ${a.state}, not established'
		}
	}
	if stream_identifier >= a.config.streams {
		return AssociationError{
			reason: .no_stream
			detail: 'stream ${stream_identifier} is outside the ${a.config.streams} negotiated'
		}
	}
	if data.len > a.config.max_message_size {
		return AssociationError{
			reason: .too_large
			detail: '${data.len} bytes exceeds the ${a.config.max_message_size}-byte maximum'
		}
	}

	// An empty message cannot be sent as an empty DATA chunk, which RFC 4960
	// forbids. RFC 8831 gives it a payload of one padding byte and a distinct
	// protocol identifier so the receiver knows to discard the byte.
	mut body := data.clone()
	mut ppid := payload_protocol_identifier
	if body.len == 0 {
		body = [u8(0)]
		ppid = match payload_protocol_identifier {
			ppid_string { ppid_string_empty }
			ppid_binary { ppid_binary_empty }
			else { payload_protocol_identifier }
		}
	}

	mut stream := a.outbound[stream_identifier] or {
		OutboundStream{
			identifier: stream_identifier
		}
	}
	sequence := if ordered { stream.next_sequence_number() } else { u16(0) }
	a.outbound[stream_identifier] = stream

	policy := a.reliability[stream_identifier] or { Reliability{} }
	mut deadline := ?time.Time(none)
	if lifetime := policy.max_packet_lifetime {
		deadline = time.now().add(lifetime)
	}

	limit := a.payload_limit()
	mut offset := 0
	for offset < body.len {
		mut chunk := body.len - offset
		if chunk > limit {
			chunk = limit
		}
		a.pending << Data{
			tsn:                         a.my_next_tsn
			stream_identifier:           stream_identifier
			stream_sequence_number:      sequence
			payload_protocol_identifier: ppid
			user_data:                   body[offset..offset + chunk].clone()
			beginning:                   offset == 0
			end:                         offset + chunk >= body.len
			unordered:                   !ordered
		}
		if at := deadline {
			a.pending_deadlines[a.my_next_tsn] = at
		}
		a.my_next_tsn++
		offset += chunk
	}

	a.fill_congestion_window()
	a.flush()
}

// recv returns the next complete message, waiting up to timeout.
pub fn (mut a Association) recv(timeout time.Duration) !Message {
	if a.is_closed() {
		return AssociationError{
			reason: .closed
			detail: 'the association is closed'
		}
	}
	select {
		message := <-a.delivered {
			return message
		}
		timeout {
			return AssociationError{
				reason: .timed_out
				detail: 'no message within ${timeout.milliseconds()}ms'
			}
		}
	}
	return AssociationError{
		reason: .closed
		detail: 'the association is closed'
	}
}