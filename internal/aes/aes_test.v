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

fn test_a_key_of_the_wrong_length_is_refused() {
	for length in [0, 1, 15, 17, 31, 33] {
		if _ := Cipher.new([]u8{len: length}) {
			assert false, '${length} bytes should not be accepted as an AES key'
		}
	}
}

fn test_encrypt_block_refuses_a_short_block() {
	cipher_ := Cipher.new([]u8{len: 16})!
	mut out := []u8{len: 16}
	if _ := cipher_.encrypt_block(mut out, []u8{len: 15}) {
		assert false, 'a short input block should be refused'
	}
	mut short := []u8{len: 8}
	if _ := cipher_.encrypt_block(mut short, []u8{len: 16}) {
		assert false, 'a short output block should be refused'
	}
}

fn test_the_block_cipher_agrees_with_the_standard_library() {
	// Neither implementation is checking the other's arithmetic here - they are
	// independent, so agreeing on random keys and inputs is strong evidence
	// both are right.
	for key_length in [16, 24, 32] {
		for _ in 0 .. 64 {
			key := rand.bytes(key_length)!
			block := rand.bytes(16)!

			ours := Cipher.new(key)!
			mut mine := []u8{len: 16}
			ours.encrypt_block(mut mine, block)!

			theirs := vlib_aes.new_cipher(key)
			mut reference := []u8{len: 16}
			theirs.encrypt(mut reference, block)

			assert mine == reference, 'disagreed on key ${bytes_to_hex(key)} block ${bytes_to_hex(block)}'
		}
	}
}