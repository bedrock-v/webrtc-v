module aes

import crypto.aes as vlib_aes
import crypto.cipher
import rand

// Tests for the block cipher and the two modes.
//
// Three kinds of check, because each catches something the others do not:
// published vectors prove the algorithm is the standard one, differential tests
// against the standard library prove it agrees with an independent
// implementation over inputs nobody chose, and the round trips prove the modes
// are inverses of each other.

fn hex_to_bytes(s string) []u8 {
	mut out := []u8{cap: s.len / 2}
	for i := 0; i + 1 < s.len; i += 2 {
		out << u8(s[i..i + 2].parse_uint(16, 8) or { panic('bad hex') })
	}
	return out
}

fn bytes_to_hex(b []u8) string {
	mut out := ''
	for value in b {
		out += value.hex_full()
	}
	return out
}

fn test_the_fips_197_aes_128_vector() {
	// FIPS-197 appendix C.1.
	cipher_ := Cipher.new(hex_to_bytes('000102030405060708090a0b0c0d0e0f'))!
	mut out := []u8{len: 16}
	cipher_.encrypt_block(mut out, hex_to_bytes('00112233445566778899aabbccddeeff'))!
	assert bytes_to_hex(out) == '69c4e0d86a7b0430d8cdb78070b4c55a'
}

fn test_the_fips_197_aes_192_vector() {
	// FIPS-197 appendix C.2. AES-192 is here because its key schedule takes a
	// different path through expand_key than either of the other two.
	cipher_ := Cipher.new(hex_to_bytes('000102030405060708090a0b0c0d0e0f1011121314151617'))!
	mut out := []u8{len: 16}
	cipher_.encrypt_block(mut out, hex_to_bytes('00112233445566778899aabbccddeeff'))!
	assert bytes_to_hex(out) == 'dda97ca4864cdfe06eaf70a0ec0d7191'
}

fn test_the_fips_197_aes_256_vector() {
	// FIPS-197 appendix C.3.
	cipher_ :=
		Cipher.new(hex_to_bytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'))!
	mut out := []u8{len: 16}
	cipher_.encrypt_block(mut out, hex_to_bytes('00112233445566778899aabbccddeeff'))!
	assert bytes_to_hex(out) == '8ea2b7ca516745bfeafc49904b496089'
}