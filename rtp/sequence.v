module rtp

import webrtc.internal.randutil

// Sequence numbers and timestamps in RTP are 16 and 32 bits wide and wrap. Any
// arithmetic on them - "is this newer", "how many did we lose" - has to account
// for that. Getting it wrong shows up as a receiver that stalls forever once a
// stream has been running long enough to wrap, which is roughly 18 minutes at
// 60 packets per second.

// Sequencer produces the sequence numbers for an outgoing stream.
//
// RFC 3550 section 5.1 requires the initial sequence number to be random, so
// that an attacker who has not seen the stream cannot inject a packet the
// receiver will accept. The same applies to the initial timestamp offset.
pub struct Sequencer {
mut:
	sequence_number u16
	roll_over_count u32
	started         bool
}