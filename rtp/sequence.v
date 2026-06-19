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

// Sequencer.new returns a sequencer starting from a random point.
pub fn Sequencer.new() !Sequencer {
	start := randutil.next_u16()!
	return Sequencer{
		sequence_number: start
		started:         false
	}
}

// Sequencer.starting_at returns a sequencer with a chosen initial value. It
// exists for tests and for resuming a stream; new streams should use
// Sequencer.new.
pub fn Sequencer.starting_at(sequence_number u16) Sequencer {
	return Sequencer{
		sequence_number: sequence_number
		started:         false
	}
}

// next returns the sequence number for the next packet.
pub fn (mut s Sequencer) next() u16 {
	if !s.started {
		s.started = true
		return s.sequence_number
	}
	s.sequence_number++
	if s.sequence_number == 0 {
		s.roll_over_count++
	}
	return s.sequence_number
}

// roll_over_count returns how many times the sequence number has wrapped. SRTP
// needs it to build the 48-bit packet index that its ciphers are keyed on.
@[inline]
pub fn (s &Sequencer) roll_over_count() u32 {
	return s.roll_over_count
}

// is_newer_sequence reports whether a is newer than b, treating the 16-bit
// space as circular (RFC 1982 serial number arithmetic).
//
// Exactly half the space is "newer" and half is "older"; the antipodal value is
// arbitrarily called older, which is the convention every RTP stack uses.
@[inline]
pub fn is_newer_sequence(a u16, b u16) bool {
	diff := u16(a - b)
	return diff != 0 && diff < 0x8000
}