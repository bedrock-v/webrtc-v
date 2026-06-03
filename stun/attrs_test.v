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