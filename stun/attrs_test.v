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