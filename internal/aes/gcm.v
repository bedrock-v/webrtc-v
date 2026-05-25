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