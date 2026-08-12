module datachannel

import sync
import time
import webrtc.sctp

// -- DCEP ------------------------------------------------------------------

fn test_open_round_trip() {
	open := Open{
		channel_type:          .partial_reliable_rexmit_unordered
		priority:              256
		reliability_parameter: 3
		label:                 'chat'
		protocol:              'json'
	}
	decoded := Open.decode(open.marshal()!)!

	assert decoded.channel_type == .partial_reliable_rexmit_unordered
	assert decoded.priority == 256
	assert decoded.reliability_parameter == 3
	assert decoded.label == 'chat'
	assert decoded.protocol == 'json'
}

fn test_open_with_empty_label_and_protocol() {
	open := Open{}
	decoded := Open.decode(open.marshal()!)!
	assert decoded.label == ''
	assert decoded.protocol == ''
	assert decoded.channel_type == .reliable
}

fn test_channel_type_properties() {
	// The unordered variants are the ordered ones with the high bit set, which
	// is why they are 0x80 apart rather than sequential.
	assert ChannelType.reliable.is_ordered()
	assert ChannelType.reliable.is_reliable()
	assert !ChannelType.reliable_unordered.is_ordered()
	assert ChannelType.reliable_unordered.is_reliable()
	assert ChannelType.partial_reliable_rexmit.is_ordered()
	assert !ChannelType.partial_reliable_rexmit.is_reliable()
	assert !ChannelType.partial_reliable_timed_unordered.is_ordered()
	assert !ChannelType.partial_reliable_timed_unordered.is_reliable()
}

fn test_open_rejects_malformed_input() {
	cases := [
		[]u8{}, // empty
		[u8(0x02)], // an ACK, not an OPEN
		[u8(0x03), 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // unknown channel type
		[u8(0x03), 0x00, 0, 0, 0, 0, 0, 0], // truncated header
		[u8(0x03), 0x00, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0], // label longer than the body
	]
	for encoded in cases {
		Open.decode(encoded) or { continue }
		assert false, 'expected ${encoded.hex()} to be rejected'
	}
}

fn test_open_enforces_label_limit() {
	long := Open{
		label: 'x'.repeat(max_label_bytes + 1)
	}
	long.marshal() or { return }
	assert false, 'an over-long label must be rejected'
}

fn test_ack_message() {
	assert is_ack(ack_message())
	assert !is_ack([]u8{})
	assert !is_ack([u8(0x03)])
	assert !is_ack([u8(0x02), 0x00])
}

fn test_channel_options_map_to_types() {
	assert ChannelOptions{}.channel_type()! == .reliable
	assert ChannelOptions{
		ordered: false
	}.channel_type()! == .reliable_unordered
	assert ChannelOptions{
		max_retransmits: u16(3)
	}.channel_type()! == .partial_reliable_rexmit
	assert ChannelOptions{
		max_retransmits: u16(3)
		ordered:         false
	}.channel_type()! == .partial_reliable_rexmit_unordered
	assert ChannelOptions{
		max_packet_lifetime: u16(500)
	}.channel_type()! == .partial_reliable_timed
	assert ChannelOptions{
		max_retransmits: u16(3)
	}.reliability_parameter() == 3
	assert ChannelOptions{
		max_packet_lifetime: u16(500)
	}.reliability_parameter() == 500
	assert ChannelOptions{}.reliability_parameter() == 0
}

fn test_channel_options_reject_both_limits() {
	// RFC 8832 section 6.1: a channel is reliable, retransmit-limited or
	// time-limited, never two of them.
	options := ChannelOptions{
		max_retransmits:     u16(3)
		max_packet_lifetime: u16(500)
	}
	options.channel_type() or { return }
	assert false, 'setting both reliability limits must be rejected'
}

// -- Over a real association -----------------------------------------------

struct PipeTransport {
mut:
	inbound chan []u8      = chan []u8{cap: 512}
	peer    &PipeTransport = unsafe { nil }
	mu      &sync.Mutex    = sync.new_mutex()
	closed  bool
	// drop_next discards this many outgoing datagrams, which is how a lost
	// message is arranged for.
	drop_next int
}