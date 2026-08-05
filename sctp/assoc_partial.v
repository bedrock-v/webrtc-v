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