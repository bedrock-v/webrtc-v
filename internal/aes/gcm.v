module aes

// Galois/Counter Mode (NIST SP 800-38D).
//
// GCM is CTR for confidentiality plus GHASH for authentication. GHASH is
// multiplication in GF(2^128), which is the part worth care: done bit by bit it
// is slower than the cipher it protects, so the multiplier here is the standard
// four-bit table method - sixteen precomputed multiples of the hash key, and one
// table lookup per nibble of the operand.
//
// The field's bit order is the reverse of the natural one: the specification
// numbers bits from the most significant, so a "shift left" in the field is a
// shift right in a register. Everything below is written in that reversed
// convention, which is why the doubling looks upside down.

// gcm_tag_size is the authentication tag length in bytes. GCM allows shorter
// tags; nothing in WebRTC uses them, and a short tag weakens forgery resistance
// far more than its length suggests.
pub const gcm_tag_size = 16

// gcm_standard_nonce_size is the 96-bit nonce every protocol here uses.
pub const gcm_standard_nonce_size = 12

// FieldElement is a GF(2^128) value, most significant half first.
struct FieldElement {
mut:
	high u64
	low  u64
}

// Gcm is AES-GCM under one key.
pub struct Gcm {
mut:
	cipher &Cipher = unsafe { nil }
	// products[i] is the hash key multiplied by i, indexed by the bit-reversed
	// nibble so that the multiplier can index it with the raw nibble.
	products [16]FieldElement
}

// Gcm.new prepares GCM for a 16, 24 or 32 byte key.
pub fn Gcm.new(key []u8) !&Gcm {
	cipher := Cipher.new(key)!
	return Gcm.with_cipher(cipher)
}

// Gcm.with_cipher reuses an already expanded key.
pub fn Gcm.with_cipher(cipher &Cipher) !&Gcm {
	mut g := &Gcm{
		cipher: unsafe { cipher }
	}

	// The hash key is the cipher applied to a block of zeros.
	mut hash_key := []u8{len: block_size}
	g.cipher.encrypt_block(mut hash_key, []u8{len: block_size})!
	key_element := FieldElement{
		high: load_u64(hash_key, 0)
		low:  load_u64(hash_key, 8)
	}

	g.products[reverse_nibble(1)] = key_element
	for i := 2; i < 16; i += 2 {
		g.products[reverse_nibble(i)] = double_element(g.products[reverse_nibble(i / 2)])
		g.products[reverse_nibble(i + 1)] = add_elements(g.products[reverse_nibble(i)], key_element)
	}
	return g
}

// seal encrypts and authenticates, returning the ciphertext with the tag
// appended.
pub fn (mut g Gcm) seal(plaintext []u8, nonce []u8, additional_data []u8) ![]u8 {
	counter := g.initial_counter(nonce)!

	mut tag_mask := []u8{len: block_size}
	g.cipher.encrypt_block(mut tag_mask, counter)!

	mut stream_counter := counter.clone()
	increment(mut stream_counter)
	mut ctr := Ctr.new(g.cipher, stream_counter)!

	mut out := []u8{len: plaintext.len + gcm_tag_size}
	mut body := unsafe { out[..plaintext.len] }
	ctr.xor_key_stream(mut body, plaintext)!

	tag := g.tag(tag_mask, additional_data, body)!
	for i in 0 .. gcm_tag_size {
		out[plaintext.len + i] = tag[i]
	}
	return out
}

// open authenticates and decrypts. The tag is expected at the end of the input.
//
// The tag is checked before anything is returned, and compared in constant
// time: a comparison that stops at the first wrong byte tells an attacker how
// much of a forged tag was right, which is enough to find the rest.
pub fn (mut g Gcm) open(ciphertext []u8, nonce []u8, additional_data []u8) ![]u8 {
	if ciphertext.len < gcm_tag_size {
		return error('aes: ${ciphertext.len} bytes is too short to hold a GCM tag')
	}
	body_len := ciphertext.len - gcm_tag_size
	body := ciphertext[..body_len]
	expected := ciphertext[body_len..]

	counter := g.initial_counter(nonce)!
	mut tag_mask := []u8{len: block_size}
	g.cipher.encrypt_block(mut tag_mask, counter)!

	tag := g.tag(tag_mask, additional_data, body)!
	if !constant_time_equal(tag, expected) {
		return error('aes: the GCM authentication tag does not match')
	}

	mut stream_counter := counter.clone()
	increment(mut stream_counter)
	mut ctr := Ctr.new(g.cipher, stream_counter)!
	mut out := []u8{len: body_len}
	ctr.xor_key_stream(mut out, body)!
	return out
}

// initial_counter derives the first counter block from the nonce.
//
// A 96-bit nonce is used directly with a counter of one, which is the case
// every protocol here hits. Any other length is folded through GHASH, which is
// what makes GCM safe for nonces it cannot simply concatenate.
fn (mut g Gcm) initial_counter(nonce []u8) ![]u8 {
	if nonce.len == 0 {
		return error('aes: a GCM nonce may not be empty')
	}
	mut counter := []u8{len: block_size}
	if nonce.len == gcm_standard_nonce_size {
		for i in 0 .. gcm_standard_nonce_size {
			counter[i] = nonce[i]
		}
		counter[15] = 1
		return counter
	}

	mut hash := FieldElement{}
	g.update(mut hash, nonce)
	mut length_block := []u8{len: block_size}
	store_u64(mut length_block, 8, u64(nonce.len) * 8)
	g.update(mut hash, length_block)
	store_u64(mut counter, 0, hash.high)
	store_u64(mut counter, 8, hash.low)
	return counter
}