module sctp

import time

// Partial reliability on the sending side (RFC 3758).
//
// A stream can be told to give up on a message after a number of
// retransmissions or after a deadline. That is what `maxRetransmits` and
// `maxPacketLifeTime` on a data channel are built from, and without it an
// "unreliable" channel is only unreliable in the SDP.
//
// Giving up is not a local matter. The receiver is waiting for those transmission
// sequence numbers and will hold every later message on the stream behind the
// gap, so abandoning has to be announced with FORWARD_TSN. Two rules follow, and
// both are load-bearing:
//
//   - A whole message is abandoned, never part of one. Half a message would be
//     reassembled into corrupt data.
//   - Nothing is abandoned unless the peer advertised FORWARD_TSN support in its
//     INIT. Against a peer that did not, partial reliability degrades to
//     reliable delivery, which is what RFC 3758 section 3.1 requires.

// Reliability is how hard the association should try to deliver a stream's
// messages.
//
// The zero value is full reliability, which is what a stream has until told
// otherwise.
@[params]
pub struct Reliability {
pub:
	// max_retransmits abandons a message once a fragment of it has been resent
	// this many times. Zero means a message is sent once and never resent.
	max_retransmits ?u16
	// max_packet_lifetime abandons a message this long after it was queued.
	max_packet_lifetime ?time.Duration
}

// is_reliable reports whether this policy ever gives up.
@[inline]
pub fn (r Reliability) is_reliable() bool {
	return r.max_retransmits == none && r.max_packet_lifetime == none
}

// abandoned_chunk is what has to be remembered about a chunk after it is
// dropped: enough to tell the peer which stream to skip and how far.
struct AbandonedChunk {
	stream_identifier      u16
	stream_sequence_number u16
	unordered              bool
}

// set_stream_reliability sets the delivery policy for one stream.
//
// It applies to messages queued after it, not to messages already in flight:
// changing the policy underneath a message that is halfway out would give its
// fragments two different deadlines.
pub fn (mut a Association) set_stream_reliability(stream_identifier u16, reliability Reliability) {
	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	if reliability.is_reliable() {
		a.reliability.delete(stream_identifier)
		return
	}
	a.reliability[stream_identifier] = reliability
}

// stream_reliability returns the policy in force for a stream.
pub fn (mut a Association) stream_reliability(stream_identifier u16) Reliability {
	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	return a.reliability[stream_identifier] or { Reliability{} }
}

// expire_queued abandons messages whose deadline passed before they were ever
// sent.
//
// A message can spend its whole lifetime waiting behind a full congestion
// window. Sending it once the deadline has gone by is worse than useless: it is
// too late to be wanted and still costs the bandwidth that the next message
// needs. The caller must hold the mutex.
fn (mut a Association) expire_queued() {
	if a.pending_deadlines.len == 0 || !a.peer_supports_forward_tsn || !a.config.partial_reliability {
		return
	}
	now := time.now()
	mut expired := []u32{}
	for tsn, deadline in a.pending_deadlines {
		if now >= deadline {
			expired << tsn
		}
	}
	for tsn in expired {
		a.pending_deadlines.delete(tsn)
		if a.fragment_at(tsn) == none {
			continue
		}
		a.abandon_message(tsn)
	}
	if expired.len > 0 {
		a.advance_forward_point()
	}
}

// should_abandon reports whether a chunk has exhausted its stream's policy.
// The caller must hold the mutex.
fn (mut a Association) should_abandon(chunk InflightChunk) bool {
	if !a.peer_supports_forward_tsn || !a.config.partial_reliability {
		return false
	}
	if limit := chunk.max_retransmits {
		if chunk.retransmits >= int(limit) {
			return true
		}
	}
	if deadline := chunk.expires_at {
		if time.now() >= deadline {
			return true
		}
	}
	return false
}

// abandon_message drops every fragment of the message containing tsn.
//
// Fragments are contiguous in transmission sequence number, so the message is
// found by walking out from this one to the fragment marked as the beginning
// and the one marked as the end. Both directions have to look in the queue as
// well as in flight: a large message can be half sent.
//
// The caller must hold the mutex.
fn (mut a Association) abandon_message(tsn u32) {
	start := a.walk_to_message_start(tsn)
	end := a.walk_to_message_end(tsn)

	mut current := start
	for {
		a.abandon_chunk(current)
		if current == end {
			break
		}
		current++
	}
}

// walk_to_message_start finds the first fragment of the message holding tsn.
fn (mut a Association) walk_to_message_start(tsn u32) u32 {
	mut current := tsn
	for {
		data := a.fragment_at(current) or { return current }
		if data.beginning {
			return current
		}
		// Guard against walking off the bottom: anything at or below the peer's
		// cumulative acknowledgement is already delivered and is not ours to
		// abandon.
		if !tsn_after(current, a.peer_cumulative_ack + 1) {
			return current
		}
		current--
	}
	return current
}

// walk_to_message_end finds the last fragment of the message holding tsn.
fn (mut a Association) walk_to_message_end(tsn u32) u32 {
	mut current := tsn
	for {
		data := a.fragment_at(current) or { return current }
		if data.end {
			return current
		}
		next := current + 1
		if a.fragment_at(next) == none {
			// The rest of the message has not been queued yet. Abandoning what
			// exists would leave the receiver holding a fragment of a message
			// whose tail is still coming, so stop here.
			return current
		}
		current = next
	}
	return current
}

// fragment_at returns the DATA chunk with this TSN, whether it is queued or in
// flight.
fn (a &Association) fragment_at(tsn u32) ?Data {
	if chunk := a.inflight[tsn] {
		return chunk.data
	}
	for pending in a.pending {
		if pending.tsn == tsn {
			return pending
		}
	}
	return none
}

// abandon_chunk removes one fragment and records what the peer must skip.
fn (mut a Association) abandon_chunk(tsn u32) {
	data := a.fragment_at(tsn) or { return }
	a.inflight.delete(tsn)
	for index, pending in a.pending {
		if pending.tsn == tsn {
			a.pending.delete(index)
			break
		}
	}
	a.abandoned[tsn] = AbandonedChunk{
		stream_identifier:      data.stream_identifier
		stream_sequence_number: data.stream_sequence_number
		unordered:              data.unordered
	}
}

// advance_forward_point moves the point below which everything is finished, and
// tells the peer if it moved.
//
// The point may pass a transmission sequence number that was abandoned or one
// the peer has already acknowledged in a gap block; anything else is still
// owed. The caller must hold the mutex.
fn (mut a Association) advance_forward_point() {
	if a.abandoned.len == 0 {
		return
	}

	mut point := a.peer_cumulative_ack
	for {
		next := point + 1
		// Named rather than `_`: V 0.5.2's if-guard with a discard binding on a
		// map lookup succeeds whether or not the key is there, which quietly
		// advanced this point over data that was still owed.
		if _ok := a.abandoned[next] {
			point = next
			continue
		}
		if chunk := a.inflight[next] {
			if chunk.acked {
				point = next
				continue
			}
		}
		break
	}

	if !tsn_after(point, a.peer_cumulative_ack) {
		return
	}
	a.forward_point = point
	a.queue_forward_tsn()
}

// queue_forward_tsn builds the chunk that tells the peer to skip ahead.
//
// One entry per ordered stream, carrying the highest sequence number abandoned
// on it. Unordered messages need no entry - there is no per-stream order for
// them to block - but their transmission sequence numbers still have to be
// covered by the cumulative point.
fn (mut a Association) queue_forward_tsn() {
	mut highest := map[u16]u16{}
	for tsn, chunk in a.abandoned {
		if chunk.unordered {
			continue
		}
		if tsn_after(tsn, a.forward_point) {
			continue
		}
		if current := highest[chunk.stream_identifier] {
			if !sequence_after(chunk.stream_sequence_number, current) {
				continue
			}
		}
		highest[chunk.stream_identifier] = chunk.stream_sequence_number
	}

	mut streams := []ForwardTsnStream{cap: highest.len}
	for identifier, sequence in highest {
		streams << ForwardTsnStream{
			identifier:      identifier
			sequence_number: sequence
		}
	}

	forward := ForwardTsn{
		new_cumulative_tsn: a.forward_point
		streams:            streams
	}
	a.control_queue << RawChunk{
		typ:   u8(ChunkType.forward_tsn)
		value: forward.marshal() or { return }
	}
	a.log.debug('abandoned up to TSN ${a.forward_point}, ${streams.len} ordered streams skipped')
}

// release_abandoned forgets abandoned chunks the peer has acknowledged past.
// The caller must hold the mutex.
fn (mut a Association) release_abandoned(cumulative u32) {
	if a.abandoned.len == 0 {
		return
	}
	mut done := []u32{}
	for tsn, _ in a.abandoned {
		if !tsn_after(tsn, cumulative) {
			done << tsn
		}
	}
	for tsn in done {
		a.abandoned.delete(tsn)
	}
}
