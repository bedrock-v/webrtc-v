module rtp

import encoding.hex

// A minimal packet: version 2, no padding, no extension, no CSRC, payload type
// 96, sequence 27035, timestamp 0xd9c8dd1a, SSRC 0x1c64b0d4, four payload bytes.
const minimal_packet = '8060699b' + 'd9c8dd1a' + '1c64b0d4' + '98364323'

fn test_decode_minimal_packet() {
	raw := hex.decode(minimal_packet)!
	p := Packet.decode(raw)!

	assert p.header.version == 2
	assert !p.header.padding
	assert !p.header.marker
	assert p.header.payload_type == 96
	assert p.header.sequence_number == 27035
	assert p.header.timestamp == 0xd9c8dd1a
	assert p.header.ssrc == 0x1c64b0d4
	assert p.header.csrc.len == 0
	assert p.payload == [u8(0x98), 0x36, 0x43, 0x23]
	assert p.padding_size == 0
}

fn test_round_trip_minimal_packet() {
	raw := hex.decode(minimal_packet)!
	p := Packet.decode(raw)!
	assert p.marshal()!.hex() == minimal_packet
	assert p.marshal_size() == raw.len
}