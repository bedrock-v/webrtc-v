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

// tag computes the authentication tag over the additional data and ciphertext.
fn (mut g Gcm) tag(mask []u8, additional_data []u8, ciphertext []u8) ![]u8 {
	mut hash := FieldElement{}
	g.update(mut hash, additional_data)
	g.update(mut hash, ciphertext)

	// The final block is the two lengths in bits. Including them is what stops
	// an attacker from moving bytes between the authenticated data and the
	// ciphertext without changing the tag.
	mut lengths := []u8{len: block_size}
	store_u64(mut lengths, 0, u64(additional_data.len) * 8)
	store_u64(mut lengths, 8, u64(ciphertext.len) * 8)
	g.update(mut hash, lengths)

	mut out := []u8{len: gcm_tag_size}
	store_u64(mut out, 0, hash.high)
	store_u64(mut out, 8, hash.low)
	for i in 0 .. gcm_tag_size {
		out[i] ^= mask[i]
	}
	return out
}

// update absorbs data into the hash, a block at a time, zero-padding a short
// final block.
@[direct_array_access]
fn (mut g Gcm) update(mut hash FieldElement, data []u8) {
	mut offset := 0
	for offset + block_size <= data.len {
		hash.high ^= load_u64(data, offset)
		hash.low ^= load_u64(data, offset + 8)
		g.multiply(mut hash)
		offset += block_size
	}
	if offset < data.len {
		mut last := []u8{len: block_size}
		for i in 0 .. data.len - offset {
			last[i] = data[offset + i]
		}
		hash.high ^= load_u64(last, 0)
		hash.low ^= load_u64(last, 8)
		g.multiply(mut hash)
	}
}

// multiply replaces x with x multiplied by the hash key.
//
// Four bits of the operand are consumed per step: the accumulator is shifted
// down by a nibble, reduced through the precomputed reduction table, and the
// matching multiple of the key is added in.
@[direct_array_access]
fn (mut g Gcm) multiply(mut x FieldElement) {
	mut z := FieldElement{}
	// The operand's halves are consumed high-degree end first, because the
	// accumulator is shifted up on every step: whatever is added last is
	// shifted least. Taking them the other way round produces a plausible
	// looking hash that matches nothing.
	mut words := [2]u64{}
	words[0] = x.low
	words[1] = x.high

	for i in 0 .. 2 {
		mut word := words[i]
		for _ in 0 .. 16 {
			nibble := z.low & 0xf
			z.low >>= 4
			z.low |= z.high << 60
			z.high >>= 4
			z.high ^= u64(gcm_reduction[nibble]) << 48

			product := g.products[word & 0xf]
			z.high ^= product.high
			z.low ^= product.low
			word >>= 4
		}
	}
	x.high = z.high
	x.low = z.low
}

// gcm_reduction[i] is the reduction of a four-bit overflow, so that the shift
// in multiply can be corrected with one lookup instead of four conditional
// exclusive-ors.
const gcm_reduction = [u16(0x0000), 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0, 0xe100,
	0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0]