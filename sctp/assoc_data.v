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

// build_sack assembles the acknowledgement for the current receive state.
fn (mut a Association) build_sack() RawChunk {
	mut sack := Sack{
		cumulative_tsn_ack:         a.last_received_tsn
		advertised_receiver_window: a.available_receive_window()
		duplicate_tsns:             a.seen_duplicates.clone()
	}
	a.seen_duplicates.clear()
	a.data_since_sack = 0

	// Gap blocks name the runs that arrived above the cumulative point, as
	// offsets from it, so the sender knows exactly what is missing.
	if a.out_of_order.len > 0 {
		mut tsns := []u32{cap: a.out_of_order.len}
		for tsn, _ in a.out_of_order {
			tsns << tsn
		}
		tsns.sort_with_compare(fn (x &u32, y &u32) int {
			if tsn_before(*x, *y) {
				return -1
			}
			if tsn_after(*x, *y) {
				return 1
			}
			return 0
		})

		mut run_start := tsns[0]
		mut run_end := tsns[0]
		for tsn in tsns[1..] {
			if tsn == run_end + 1 {
				run_end = tsn
				continue
			}
			sack.gap_ack_blocks << a.gap_block(run_start, run_end)
			run_start = tsn
			run_end = tsn
		}
		sack.gap_ack_blocks << a.gap_block(run_start, run_end)
	}

	return RawChunk{
		typ:   u8(ChunkType.sack)
		value: sack.marshal() or { []u8{} }
	}
}

fn (mut a Association) gap_block(start u32, end u32) GapAckBlock {
	return GapAckBlock{
		start: u16(tsn_distance(start, a.last_received_tsn))
		end:   u16(tsn_distance(end, a.last_received_tsn))
	}
}

// available_receive_window is what is left of the advertised buffer.
//
// Reporting it honestly is what makes back pressure work: a peer that is told
// there is no room stops sending, and the application's own slowness reaches
// the sender instead of being absorbed by an unbounded queue.
fn (mut a Association) available_receive_window() u32 {
	mut used := u32(0)
	for _, data in a.out_of_order {
		used += u32(data.user_data.len)
	}
	for message in a.held {
		used += u32(message.data.len)
	}
	if used >= a.my_receive_window {
		return 0
	}
	return a.my_receive_window - used
}

// handle_sack processes an acknowledgement from the peer.
fn (mut a Association) handle_sack(sack Sack) {
	if tsn_before(sack.cumulative_tsn_ack, a.peer_cumulative_ack) {
		// An acknowledgement older than one already processed. Acting on it
		// would move the window backwards.
		return
	}
	a.peer_cumulative_ack = sack.cumulative_tsn_ack
	a.peer_receive_window = sack.advertised_receiver_window
	a.release_abandoned(sack.cumulative_tsn_ack)
	if tsn_before(sack.cumulative_tsn_ack, a.forward_point) {
		// The peer is still behind the point it was told to skip to, so its
		// FORWARD_TSN was lost. RFC 3758 section 3.5 says to send it again.
		a.queue_forward_tsn()
	}

	mut newly_acked := u32(0)
	mut rtt_sample := time.Duration(0)
	mut have_sample := false

	// Everything at or below the cumulative point is done with.
	mut done := []u32{}
	for tsn, chunk in a.inflight {
		if tsn_after(tsn, sack.cumulative_tsn_ack) {
			continue
		}
		done << tsn
		if !chunk.acked {
			newly_acked += u32(chunk.data.user_data.len)
		}
		// Only a chunk that was sent once gives a usable round-trip
		// measurement; for a retransmitted one there is no way to tell which
		// transmission the acknowledgement answers (Karn's algorithm).
		if chunk.retransmits == 0 && !have_sample {
			rtt_sample = time.now() - chunk.sent_at
			have_sample = true
		}
	}
	for tsn in done {
		a.inflight.delete(tsn)
	}

	// Gap blocks mark chunks as received without retiring them: the peer may
	// still renege, and only the cumulative point is a promise.
	for block in sack.gap_ack_blocks {
		start := sack.cumulative_tsn_ack + u32(block.start)
		end := sack.cumulative_tsn_ack + u32(block.end)
		mut tsn := start
		for !tsn_after(tsn, end) {
			if mut chunk := a.inflight[tsn] {
				if !chunk.acked {
					chunk.acked = true
					newly_acked += u32(chunk.data.user_data.len)
					a.inflight[tsn] = chunk
				}
			}
			tsn++
		}
	}
	a.count_missing_reports(sack)

	if have_sample {
		a.update_rto(rtt_sample)
	}
	a.grow_congestion_window(newly_acked)
	a.fill_congestion_window()
}

// count_missing_reports marks chunks the peer has now reported missing more
// than once, and retransmits those that cross the threshold.
fn (mut a Association) count_missing_reports(sack Sack) {
	if sack.gap_ack_blocks.len == 0 {
		return
	}
	// The highest TSN named by any gap block. Anything below it that has not
	// been acknowledged is genuinely missing rather than merely in flight.
	mut highest := sack.cumulative_tsn_ack
	for block in sack.gap_ack_blocks {
		candidate := sack.cumulative_tsn_ack + u32(block.end)
		if tsn_after(candidate, highest) {
			highest = candidate
		}
	}

	mut resend := []u32{}
	for tsn, mut chunk in a.inflight {
		if chunk.acked || !tsn_before(tsn, highest) {
			continue
		}
		chunk.missing_reports++
		a.inflight[tsn] = chunk
		if chunk.missing_reports >= fast_retransmit_threshold {
			resend << tsn
		}
	}
	if resend.len == 0 {
		return
	}

	// A fast retransmit halves the window rather than collapsing it, because
	// the acknowledgements prove the path is still carrying traffic.
	a.slow_start_threshold = max_u32(a.congestion_window / 2, u32(4 * a.transport.max_write()))
	a.congestion_window = a.slow_start_threshold

	for tsn in resend {
		mut chunk := a.inflight[tsn] or { continue }
		if a.should_abandon(chunk) {
			a.abandon_message(tsn)
			continue
		}
		chunk.missing_reports = 0
		chunk.retransmits++
		chunk.sent_at = time.now()
		a.inflight[tsn] = chunk
		a.control_queue << RawChunk{
			typ:   u8(ChunkType.data)
			flags: chunk.data.flags()
			value: chunk.data.marshal() or { continue }
		}
		a.log.debug('fast retransmit of TSN ${tsn}')
	}
	a.advance_forward_point()
}