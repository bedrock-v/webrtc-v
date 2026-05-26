module randutil

fn test_bytes_length_and_edge_cases() {
	assert bytes(0)!.len == 0
	assert bytes(1)!.len == 1
	assert bytes(64)!.len == 64
	bytes(-1) or { return }
	assert false, 'negative length must be rejected'
}

fn test_string_uses_only_alphabet() {
	alphabet := 'abc'.bytes()
	s := chars(200, alphabet)!
	assert s.len == 200
	for c in s.bytes() {
		assert c in alphabet
	}
}