module stun

fn test_error_code_round_trip() {
	codes := [300, 400, 401, 420, 438, 487, 500, 699]
	for code in codes {
		mut msg := Message.new(.error_response, .binding)!
		msg.add_error_code(code, '')!
		decoded := Message.decode(msg.encode()!)!
		got := decoded.error_code()!
		assert got.code == code
		assert got.reason == default_reason(code)
	}
}

fn test_error_code_custom_reason() {
	mut msg := Message.new(.error_response, .binding)!
	msg.add_error_code(487, 'Role Conflict')!
	decoded := Message.decode(msg.encode()!)!
	got := decoded.error_code()!
	assert got.code == 487
	assert got.reason == 'Role Conflict'
	assert got.str() == '487 Role Conflict'
	assert got.msg() == 'stun: 487 Role Conflict'
}

fn test_error_code_rejects_out_of_range() {
	for code in [0, 99, 299, 700, -1] {
		mut msg := Message.new(.error_response, .binding)!
		msg.add_error_code(code, 'x') or { continue }
		assert false, 'code ${code} must be rejected'
	}
}

fn test_error_code_rejects_malformed_wire_value() {
	cases := [
		[]u8{},
		[u8(0), 0, 0],
		[u8(0), 0, 2, 0], // class 2 is below the 300 floor
		[u8(0), 0, 7, 0], // class 7 is above the 699 ceiling
		[u8(0), 0, 4, 100], // number above 99
		[u8(0), 0, 4, 0, 0xff, 0xfe], // invalid UTF-8 reason
	]
	for value in cases {
		mut msg := Message.new(.error_response, .binding)!
		msg.add(attr_error_code, value)
		decoded := Message.decode(msg.encode()!)!
		decoded.error_code() or { continue }
		assert false, 'expected ${value.hex()} to be rejected'
	}
}

fn test_error_code_absent() {
	msg := Message.new(.error_response, .binding)!
	msg.error_code() or {
		assert err is AttributeNotFoundError
		return
	}
	assert false, 'missing ERROR-CODE must be reported'
}

fn test_unknown_attributes_round_trip() {
	mut msg := Message.new(.error_response, .binding)!
	msg.add_error_code(code_unknown_attribute, '')!
	msg.add_unknown_attributes([u16(0x0024), 0x0025, 0x7FFF])

	decoded := Message.decode(msg.encode()!)!
	assert decoded.unknown_attributes()! == [u16(0x0024), 0x0025, 0x7FFF]
}

fn test_unknown_attributes_rejects_odd_length() {
	mut msg := Message.new(.error_response, .binding)!
	msg.add(attr_unknown_attributes, [u8(0x00), 0x24, 0x00])
	decoded := Message.decode(msg.encode()!)!
	decoded.unknown_attributes() or {
		assert err is DecodeError
		return
	}
	assert false, 'odd-length UNKNOWN-ATTRIBUTES must be rejected'
}

fn test_text_attributes_round_trip() {
	mut msg := Message.new(.request, .allocate)!
	msg.add_username('user:name')!
	msg.add_realm('example.org')!
	msg.add_nonce('f//49k954d6OL34oL9FSTvy64sA')!
	msg.add_software('webrtc-v test')!

	decoded := Message.decode(msg.encode()!)!
	assert decoded.username()! == 'user:name'
	assert decoded.realm()! == 'example.org'
	assert decoded.nonce()! == 'f//49k954d6OL34oL9FSTvy64sA'
	assert decoded.software()! == 'webrtc-v test'
}

fn test_text_attributes_accept_utf8() {
	// RFC 5769 section 2.4 uses a Japanese username, so multi-byte text must
	// survive the round trip unchanged.
	name := 'マトリックス'
	mut msg := Message.new(.request, .allocate)!
	msg.add_username(name)!
	decoded := Message.decode(msg.encode()!)!
	assert decoded.username()! == name
}

fn test_text_attributes_reject_invalid_utf8() {
	bad := [
		[u8(0xff)], // never valid
		[u8(0xc0), 0x80], // overlong encoding of NUL
		[u8(0xe0), 0x80, 0x80], // overlong
		[u8(0xed), 0xa0, 0x80], // UTF-16 surrogate half
		[u8(0xf5), 0x80, 0x80, 0x80], // above U+10FFFF
		[u8(0xc2)], // truncated two-byte sequence
		[u8(0xe2), 0x82], // truncated three-byte sequence
		[u8(0x41), 0xc2], // valid ASCII then a truncated sequence
	]
	for value in bad {
		mut msg := Message.new(.request, .allocate)!
		msg.add(attr_username, value)
		decoded := Message.decode(msg.encode()!)!
		decoded.username() or { continue }
		assert false, 'expected ${value.hex()} to be rejected as UTF-8'
	}
}

fn test_text_attributes_accept_valid_utf8_boundaries() {
	good := [
		'a', // one byte
		'é', // two bytes
		'€', // three bytes
		'\U0001F600', // four bytes
		'', // empty
	]
	for s in good {
		assert is_valid_utf8(s.bytes()), '${s.bytes().hex()} should be valid UTF-8'
	}
}