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