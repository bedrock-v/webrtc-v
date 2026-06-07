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