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

fn test_the_gcm_all_zero_vectors() {
	// Test cases 1 and 2 from the GCM specification's own vectors: an empty
	// message and a single zero block, both under a zero key and nonce.
	mut gcm := Gcm.new([]u8{len: 16})!

	empty := gcm.seal([]u8{}, []u8{len: 12}, []u8{})!
	assert bytes_to_hex(empty) == '58e2fccefa7e3061367f1d57a4e7455a'

	one_block := gcm.seal([]u8{len: 16}, []u8{len: 12}, []u8{})!
	assert bytes_to_hex(one_block) == '0388dace60b6a392f328c2b971b2fe78' +
		'ab6e47d42cec13bdf53a67b21257bddf'
}

fn test_gcm_agrees_with_the_standard_library() {
	for key_length in [16, 32] {
		for size in [0, 1, 15, 16, 17, 63, 64, 1163] {
			key := rand.bytes(key_length)!
			nonce := rand.bytes(12)!
			plaintext := rand.bytes(size)!
			additional := rand.bytes(size % 29)!

			mut ours := Gcm.new(key)!
			mine := ours.seal(plaintext, nonce, additional)!

			theirs := vlib_aes.new_aes_gcm(key)!
			reference := theirs.encrypt(plaintext, nonce, additional)!

			assert mine == reference, 'disagreed at ${size} bytes with a ${key_length}-byte key'
		}
	}
}

fn test_gcm_opens_what_the_standard_library_sealed() {
	// The other direction, so that a mistake shared between our own seal and
	// open - which would round trip perfectly - cannot hide.
	key := rand.bytes(16)!
	nonce := rand.bytes(12)!
	plaintext := rand.bytes(200)!
	additional := rand.bytes(13)!

	theirs := vlib_aes.new_aes_gcm(key)!
	sealed := theirs.encrypt(plaintext, nonce, additional)!

	mut ours := Gcm.new(key)!
	opened := ours.open(sealed, nonce, additional)!
	assert opened == plaintext
}

fn test_gcm_round_trips() {
	key := rand.bytes(32)!
	nonce := rand.bytes(12)!
	plaintext := rand.bytes(4096)!
	additional := rand.bytes(20)!

	mut gcm := Gcm.new(key)!
	sealed := gcm.seal(plaintext, nonce, additional)!
	assert sealed.len == plaintext.len + gcm_tag_size
	assert gcm.open(sealed, nonce, additional)! == plaintext
}

fn test_gcm_rejects_a_tampered_message() {
	key := rand.bytes(16)!
	nonce := rand.bytes(12)!
	mut gcm := Gcm.new(key)!
	sealed := gcm.seal('the quick brown fox'.bytes(), nonce, 'header'.bytes())!

	// Every single-bit change anywhere - ciphertext or tag - must be caught.
	for index in 0 .. sealed.len {
		mut tampered := sealed.clone()
		tampered[index] ^= 0x01
		if _ := gcm.open(tampered, nonce, 'header'.bytes()) {
			assert false, 'a flipped bit at byte ${index} was not detected'
		}
	}
}

fn test_gcm_rejects_the_wrong_additional_data() {
	// The additional data is not in the message, so this is the only thing that
	// binds a packet to its header.
	key := rand.bytes(16)!
	nonce := rand.bytes(12)!
	mut gcm := Gcm.new(key)!
	sealed := gcm.seal('payload'.bytes(), nonce, 'right'.bytes())!
	if _ := gcm.open(sealed, nonce, 'wrong'.bytes()) {
		assert false, 'the wrong additional data was accepted'
	}
}

fn test_gcm_rejects_the_wrong_nonce() {
	key := rand.bytes(16)!
	mut gcm := Gcm.new(key)!
	sealed := gcm.seal('payload'.bytes(), []u8{len: 12}, []u8{})!
	mut other := []u8{len: 12}
	other[11] = 1
	if _ := gcm.open(sealed, other, []u8{}) {
		assert false, 'the wrong nonce was accepted'
	}
}