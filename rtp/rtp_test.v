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

fn test_marker_and_payload_type_split() {
	mut p := Packet{
		header:  Header{
			marker:       true
			payload_type: 111
		}
		payload: [u8(1)]
	}
	raw := p.marshal()!
	assert raw[1] == 0xEF // marker set, payload type 111

	back := Packet.decode(raw)!
	assert back.header.marker
	assert back.header.payload_type == 111
}

fn test_csrc_round_trip() {
	mut p := Packet{
		header:  Header{
			payload_type: 96
			csrc:         [u32(0x11111111), 0x22222222, 0x33333333]
		}
		payload: [u8(0xAA)]
	}
	raw := p.marshal()!
	assert raw[0] & 0x0F == 3
	assert raw.len == header_size + 12 + 1

	back := Packet.decode(raw)!
	assert back.header.csrc == [u32(0x11111111), 0x22222222, 0x33333333]
}

fn test_marshal_rejects_too_many_csrc() {
	mut p := Packet{
		header: Header{
			csrc: []u32{len: 16}
		}
	}
	p.marshal() or {
		assert err is EncodeError
		return
	}
	assert false, 'more than 15 CSRCs must be rejected'
}

fn test_decode_rejects_truncated_csrc_list() {
	// CC says 3, but the packet ends after the fixed header.
	raw := hex.decode('8360699bd9c8dd1a1c64b0d4')!
	Packet.decode(raw) or {
		assert err is DecodeError
		if err is DecodeError {
			assert err.reason == .bad_csrc
		}
		return
	}
	assert false, 'a truncated CSRC list must be rejected'
}

fn test_padding_is_stripped_and_restored() {
	mut p := Packet{
		header:       Header{
			payload_type: 96
		}
		payload:      [u8(1), 2, 3]
		padding_size: 4
	}
	raw := p.marshal()!
	assert raw[0] & 0x20 != 0
	assert raw.len == header_size + 3 + 4
	assert raw[raw.len - 1] == 4

	back := Packet.decode(raw)!
	assert back.payload == [u8(1), 2, 3]
	assert back.padding_size == 4
	assert back.marshal()!.hex() == raw.hex()
}

fn test_decode_rejects_bad_padding() {
	cases := {
		'padding flag with no payload':    'a060699bd9c8dd1a1c64b0d4'
		'padding length of zero':          'a060699bd9c8dd1a1c64b0d400'
		'padding longer than the payload': 'a060699bd9c8dd1a1c64b0d40105'
	}
	for name, encoded in cases {
		raw := hex.decode(encoded)!
		Packet.decode(raw) or {
			assert err is DecodeError
			continue
		}
		assert false, 'expected ${name} to be rejected'
	}
}

fn test_decode_rejects_wrong_version() {
	raw := hex.decode('4060699bd9c8dd1a1c64b0d4')!
	Packet.decode(raw) or {
		assert err is DecodeError
		if err is DecodeError {
			assert err.reason == .bad_version
		}
		return
	}
	assert false, 'version 1 must be rejected'
}

fn test_decode_rejects_short_packets() {
	for n in 0 .. header_size {
		Packet.decode([]u8{len: n, init: 0x80}) or { continue }
		assert false, 'a ${n}-byte packet must be rejected'
	}
}