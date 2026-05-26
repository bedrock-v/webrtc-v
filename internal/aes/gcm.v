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