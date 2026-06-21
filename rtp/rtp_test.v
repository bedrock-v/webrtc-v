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

fn test_one_byte_extensions_round_trip() {
	mut p := Packet{
		header:  Header{
			payload_type: 96
		}
		payload: [u8(0xFF)]
	}
	p.header.set_extension(1, [u8(0xAA)])!
	p.header.set_extension(5, [u8(0xBB), 0xCC, 0xDD])!

	assert p.header.extension_profile == extension_profile_one_byte
	assert !p.header.uses_two_byte_extensions()

	raw := p.marshal()!
	assert raw[0] & 0x10 != 0

	back := Packet.decode(raw)!
	assert back.header.extension(1)? == [u8(0xAA)]
	assert back.header.extension(5)? == [u8(0xBB), 0xCC, 0xDD]
	assert back.header.extension(9) == none
	assert back.payload == [u8(0xFF)]
}

fn test_two_byte_extensions_round_trip() {
	mut p := Packet{
		header: Header{
			payload_type:      96
			extension_profile: extension_profile_two_byte_base
		}
	}
	p.header.set_extension(200, []u8{len: 32, init: u8(index)})!
	// A zero-length payload is legal in the two-byte form and not in the
	// one-byte form, so it is a good check that the profile is honoured.
	p.header.set_extension(3, []u8{})!

	assert p.header.uses_two_byte_extensions()
	back := Packet.decode(p.marshal()!)!
	assert back.header.uses_two_byte_extensions()
	assert back.header.extension(200)?.len == 32
	assert back.header.extension(3)?.len == 0
}

fn test_extension_profile_chosen_by_first_element() {
	mut short_header := Header{}
	short_header.set_extension(3, [u8(1), 2])!
	assert short_header.extension_profile == extension_profile_one_byte

	// An id above 14 cannot be expressed in the one-byte form, so the two-byte
	// form is chosen instead.
	mut long_header := Header{}
	long_header.set_extension(20, [u8(1)])!
	assert long_header.uses_two_byte_extensions()

	// So does a payload that will not fit 16 bytes.
	mut big_header := Header{}
	big_header.set_extension(1, []u8{len: 17})!
	assert big_header.uses_two_byte_extensions()
}

fn test_set_extension_enforces_profile_limits() {
	mut h := Header{}
	h.set_extension(1, [u8(1)])!
	assert h.extension_profile == extension_profile_one_byte

	// Once the one-byte profile is fixed, an element that does not fit it is an
	// error rather than a silent upgrade that would invalidate what came first.
	h.set_extension(20, [u8(1)]) or {
		h.set_extension(2, []u8{len: 17}) or {
			h.set_extension(2, []u8{}) or {
				h.set_extension(0, [u8(1)]) or { return }
				assert false, 'id 0 must be rejected'
			}
			assert false, 'an empty one-byte payload must be rejected'
		}
		assert false, 'an over-long one-byte payload must be rejected'
	}
	assert false, 'an out-of-range one-byte id must be rejected'
}

fn test_set_extension_replaces_in_place() {
	mut h := Header{}
	h.set_extension(1, [u8(1)])!
	h.set_extension(2, [u8(2)])!
	h.set_extension(1, [u8(9), 9])!

	assert h.extensions.len == 2
	assert h.extension(1)? == [u8(9), 9]
	// Replacing must not reorder: element order is part of what the peer sees.
	assert h.extensions[0].id == 1
	assert h.extensions[1].id == 2
}

fn test_delete_extension() {
	mut h := Header{}
	h.set_extension(1, [u8(1)])!
	h.set_extension(2, [u8(2)])!

	assert h.delete_extension(1)
	assert !h.delete_extension(1)
	assert h.extension(1) == none
	assert h.extensions.len == 1
	assert h.extension_profile == extension_profile_one_byte

	// Removing the last element clears the profile, so a later element can pick
	// whichever form suits it.
	assert h.delete_extension(2)
	assert h.extension_profile == 0
}

fn test_one_byte_extension_stops_at_terminator() {
	// Profile 0xBEDE, one word: element id 1 length 1 value 0xAA, then the
	// id-15 terminator, then a byte that must not be parsed as an element.
	raw := hex.decode('9060699bd9c8dd1a1c64b0d4bede000110aaf0ff')!
	p := Packet.decode(raw)!
	assert p.header.extensions.len == 1
	assert p.header.extension(1)? == [u8(0xAA)]
}

fn test_one_byte_extension_skips_padding() {
	// Two padding bytes before the element.
	raw := hex.decode('9060699bd9c8dd1a1c64b0d4bede00010010aa00')!
	p := Packet.decode(raw)!
	assert p.header.extensions.len == 1
	assert p.header.extension(1)? == [u8(0xAA)]
}

fn test_decode_rejects_truncated_extension() {
	cases := [
		'9060699bd9c8dd1a1c64b0d4be', // profile cut in half
		'9060699bd9c8dd1a1c64b0d4bede', // no length
		'9060699bd9c8dd1a1c64b0d4bede0004', // length longer than the packet
		'9060699bd9c8dd1a1c64b0d4bede00011faa', // element declares 16 bytes, has 1
	]
	for encoded in cases {
		raw := hex.decode(encoded)!
		Packet.decode(raw) or {
			assert err is DecodeError
			continue
		}
		assert false, 'expected ${encoded} to be rejected'
	}
}

fn test_unknown_extension_profile_round_trips_opaquely() {
	// Profile 0x1234 is neither RFC 8285 form; the body is preserved whole so
	// the packet re-marshals unchanged.
	raw := hex.decode('9060699bd9c8dd1a1c64b0d41234000101020304')!
	p := Packet.decode(raw)!
	assert p.header.extension_profile == 0x1234
	assert p.header.extensions.len == 1
	assert p.header.extensions[0].payload == [u8(1), 2, 3, 4]
	assert p.marshal()!.hex() == raw.hex()
}

fn test_extension_body_is_padded_to_a_word() {
	mut h := Header{}
	// One element: 1 header byte + 1 payload byte = 2, padded to 4.
	h.set_extension(1, [u8(0xAA)])!
	body := encode_extensions(h)!
	assert body.len == 8 // 4-byte extension header + 4-byte body
	assert body[2] == 0x00 && body[3] == 0x01 // one 32-bit word
}

fn test_demultiplexing_predicates() {
	rtp_packet := hex.decode(minimal_packet)!
	assert is_rtp(rtp_packet)
	assert !is_rtcp_payload_type(rtp_packet)

	// A sender report: version 2, payload type 200.
	sr := hex.decode('80c800061c64b0d4')!
	assert is_rtcp_payload_type(sr)

	// STUN and DTLS both fall outside the 128-191 first-byte range.
	assert !is_rtp([]u8{len: 20, init: 0x00})
	assert !is_rtp([]u8{len: 20, init: 0x16})
	assert !is_rtp([]u8{len: 4, init: 0x80})
}

fn test_decode_survives_arbitrary_input() {
	mut seed := u32(0xC0FFEE)
	for _ in 0 .. 5000 {
		seed = seed * 1103515245 + 12345
		length := 8 + int(seed >> 26)
		mut raw := []u8{len: length}
		for i in 0 .. length {
			seed = seed * 1103515245 + 12345
			raw[i] = u8(seed >> 24)
		}
		// Force a valid version so more inputs get past the first check and
		// exercise the rest of the parser.
		raw[0] = (raw[0] & 0x3F) | 0x80

		p := Packet.decode(raw) or { continue }
		p.str()
		p.marshal_size()
		// Anything that decodes must also re-marshal without panicking.
		p.marshal() or { continue }
	}
}

fn test_sequence_arithmetic_across_wrap() {
	assert is_newer_sequence(2, 1)
	assert !is_newer_sequence(1, 2)
	assert !is_newer_sequence(1, 1)
	// Across the wrap: 0 is newer than 65535.
	assert is_newer_sequence(0, 65535)
	assert !is_newer_sequence(65535, 0)
	assert is_newer_sequence(5, 65530)
	// The antipode is defined as older.
	assert !is_newer_sequence(32768, 0)
	assert is_newer_sequence(32767, 0)
}

fn test_sequence_distance() {
	assert sequence_distance(10, 4) == 6
	assert sequence_distance(4, 10) == -6
	assert sequence_distance(1, 65535) == 2
	assert sequence_distance(65535, 1) == -2
	assert sequence_distance(7, 7) == 0
}

fn test_timestamp_arithmetic_across_wrap() {
	assert is_newer_timestamp(2, 1)
	assert !is_newer_timestamp(1, 2)
	assert is_newer_timestamp(0, 0xFFFFFFFF)
	assert !is_newer_timestamp(0xFFFFFFFF, 0)
}

fn test_sequencer_counts_roll_overs() {
	mut s := Sequencer.starting_at(65534)
	assert s.next() == 65534
	assert s.roll_over_count() == 0
	assert s.next() == 65535
	assert s.roll_over_count() == 0
	assert s.next() == 0
	assert s.roll_over_count() == 1
	assert s.next() == 1
	assert s.roll_over_count() == 1
}

fn test_sequencer_starts_randomly() {
	// RFC 3550 section 5.1 requires an unpredictable starting point, so that a
	// blind attacker cannot land a packet inside the receiver's window.
	mut seen := map[u16]bool{}
	for _ in 0 .. 64 {
		mut s := Sequencer.new()!
		seen[s.next()] = true
	}
	assert seen.len > 50, 'sequence numbers look predictable'
}

fn test_unwrap_sequence_follows_rfc3711_appendix_a() {
	// Ordinary progress inside a cycle.
	roc, index := unwrap_sequence(0, 100, 101)
	assert roc == 0
	assert index == 101

	// A packet just after the wrap, while the watermark is still high.
	wrapped_roc, wrapped_index := unwrap_sequence(0, 65535, 1)
	assert wrapped_roc == 1
	assert wrapped_index == 0x10001

	// A straggler from before the wrap, arriving after the watermark reset.
	late_roc, late_index := unwrap_sequence(1, 5, 65530)
	assert late_roc == 0
	assert late_index == 65530

	// The roll-over count wraps with the packet index, not independently.
	zero_roc, _ := unwrap_sequence(0, 5, 65530)
	assert zero_roc == 0xFFFFFFFF
}
