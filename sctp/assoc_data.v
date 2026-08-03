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

// try_recv returns a message if one is already queued.
pub fn (mut a Association) try_recv() ?Message {
	select {
		message := <-a.delivered {
			return message
		}
		else {
			return none
		}
	}
	return none
}

// fill_congestion_window moves queued chunks into flight, as far as the
// congestion window and the peer's advertised receive window allow.
//
// Two separate limits apply and both must be respected. The congestion window
// is what the network is believed to carry; the receive window is what the peer
// has room for. Ignoring the first congests the path, ignoring the second
// overruns the peer.
fn (mut a Association) fill_congestion_window() {
	if a.state != .established && a.state != .shutdown_pending {
		return
	}
	mut outstanding := a.bytes_in_flight()

	for a.pending.len > 0 {
		next := a.pending[0]
		size := u32(next.user_data.len)

		if outstanding + size > a.congestion_window {
			break
		}
		// The peer's window is what it said it had, less what we have already
		// sent it. A zero window still permits one chunk, which is what stops
		// the association deadlocking when the peer's window opens but the
		// notification is lost.
		if outstanding > 0 && outstanding + size > a.peer_receive_window {
			break
		}

		a.pending.delete(0)
		policy := a.reliability[next.stream_identifier] or { Reliability{} }
		// The lifetime is measured from when the application handed the message
		// over, not from when it first went out. A message that spent its
		// deadline waiting behind a full congestion window is exactly the one
		// the deadline was meant to discard.
		mut expires_at := ?time.Time(none)
		if deadline := a.pending_deadlines[next.tsn] {
			expires_at = deadline
		}
		a.pending_deadlines.delete(next.tsn)
		a.inflight[next.tsn] = InflightChunk{
			data:            next
			sent_at:         time.now()
			max_retransmits: policy.max_retransmits
			expires_at:      expires_at
		}
		a.control_queue << RawChunk{
			typ:   u8(ChunkType.data)
			flags: next.flags()
			value: next.marshal() or { continue }
		}
		outstanding += size
	}
}

// bytes_in_flight is how much unacknowledged data is outstanding.
fn (mut a Association) bytes_in_flight() u32 {
	mut total := u32(0)
	for _, chunk in a.inflight {
		if !chunk.acked {
			total += u32(chunk.data.user_data.len)
		}
	}
	return total
}

// handle_data folds an arriving DATA chunk into the receive state.
fn (mut a Association) handle_data(data Data) ! {
	if a.state != .established && a.state != .shutdown_pending && a.state != .shutdown_received {
		return
	}

	// Anything at or below the cumulative point has already been delivered.
	// Acknowledging it again is required - the peer's copy of the
	// acknowledgement was evidently lost - but delivering it again is not.
	if !tsn_after(data.tsn, a.last_received_tsn) {
		a.seen_duplicates << data.tsn
		a.schedule_sack(true)
		return
	}
	if data.tsn in a.out_of_order {
		a.seen_duplicates << data.tsn
		a.schedule_sack(true)
		return
	}
	if data.stream_identifier >= a.config.streams {
		a.log.debug('data for stream ${data.stream_identifier}, outside the ${a.config.streams} negotiated')
		a.schedule_sack(true)
		return
	}

	a.out_of_order[data.tsn] = data
	// A chunk that does not close the gap needs an immediate acknowledgement so
	// the sender can fast-retransmit rather than wait for its timer.
	gap_opened := data.tsn != a.last_received_tsn + 1
	a.advance_cumulative_ack()!

	// RFC 4960 section 6.2 requires an acknowledgement at least every second
	// packet. Waiting for the delay timer on every chunk instead would hold the
	// sender's congestion window shut and collapse throughput to one window per
	// delay interval.
	a.data_since_sack++
	send_now := gap_opened || data.immediate_sack || a.data_since_sack >= 2
	a.schedule_sack(send_now)
}

// advance_cumulative_ack moves the cumulative point over every TSN that is now
// contiguous, delivering the data as it goes.
fn (mut a Association) advance_cumulative_ack() ! {
	for {
		next := a.last_received_tsn + 1
		data := a.out_of_order[next] or { break }
		a.out_of_order.delete(next)
		a.last_received_tsn = next
		a.deliver(data)!
	}
}

// deliver hands a chunk to its stream and forwards whatever became complete.
fn (mut a Association) deliver(data Data) ! {
	mut stream := a.inbound[data.stream_identifier] or {
		InboundStream{
			identifier: data.stream_identifier
		}
	}
	messages := stream.accept(data, a.config.max_message_size) or {
		a.inbound[data.stream_identifier] = stream
		a.abort('reassembly failed: ${err.msg()}')
		return AssociationError{
			reason: .protocol
			detail: err.msg()
		}
	}
	a.inbound[data.stream_identifier] = stream

	for message in messages {
		a.forward(message)
	}
}

// forward queues a message for the application.
fn (mut a Association) forward(message Message) {
	select {
		a.delivered <- message {}
		else {
			// The application is not keeping up. Dropping here would break the
			// reliability the stream promised, so the message is kept and the
			// receive window is what tells the peer to slow down.
			a.log.warn('delivery queue full; message on stream ${message.stream_identifier} held')
			a.held << message
		}
	}
}

// schedule_sack arranges for an acknowledgement.
//
// It is delayed by default so that it can ride with outgoing data or cover
// several chunks at once, which is what RFC 4960 section 6.2 asks for. A gap or
// a duplicate cancels the delay: those are the cases where the sender is
// waiting on the answer.
fn (mut a Association) schedule_sack(now bool) {
	a.sack_pending = true
	if now {
		a.immediate_sack = true
		return
	}
	if a.sack_due_at == time.Time{} || time.now() > a.sack_due_at {
		a.sack_due_at = time.now().add(a.config.sack_delay)
	}
}