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

fn test_string_rejects_bad_alphabet() {
	chars(4, []u8{}) or {
		chars(-1, 'ab'.bytes()) or { assert false }
		return
	}
	assert false, 'empty alphabet must be rejected'
}

fn test_string_zero_length() {
	assert chars(0, 'ab'.bytes())! == ''
}

fn test_ice_credentials_meet_rfc8445_minimums() {
	ufrag := ice_ufrag()!
	pwd := ice_pwd()!
	assert ufrag.len >= 4
	assert pwd.len >= 22
	for c in ufrag.bytes() {
		assert c in ice_chars
	}
	for c in pwd.bytes() {
		assert c in ice_chars
	}
}

fn test_ice_credentials_are_not_repeated() {
	mut seen := map[string]bool{}
	for _ in 0 .. 64 {
		pwd := ice_pwd()!
		assert pwd !in seen, 'ICE password repeated within 64 draws'
		seen[pwd] = true
	}
}