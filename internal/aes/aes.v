// Package aes is AES in the encryption direction, plus the two modes this
// project needs: CTR and GCM.
//
// It exists because `crypto.aes` in the standard library is a byte-oriented
// reference implementation, and the whole stack is built on top of AES - every
// DTLS record, every SRTP packet, and the SRTP key derivation. Measured on this
// machine in a `-prod` build, `crypto.aes` does about 3.8 MB/s of block
// encryption, which caps a data channel at roughly 2 MB/s. That is the ceiling
// for everything above it, so it is worth the table-driven version.
//
// Only the forward direction is here. CTR and GCM never decrypt a block - they
// encrypt a counter and exclusive-or it with the data - so the inverse cipher
// and its tables would be dead weight.
//
// **Timing.** The tables make this vulnerable to a cache-timing attack from an
// attacker running code on the same machine, and so is the S-box lookup in the
// standard library's version; this is not a regression, but it is also not
// constant time. See SECURITY.md.
module aes

// block_size is the AES block size in bytes. It is 16 for every key length.
pub const block_size = 16

// Cipher is an expanded AES key.
//
// It holds the round keys as big-endian 32-bit words, which is the order the
// round function reads them in, so the hot loop does no byte shuffling.
pub struct Cipher {
mut:
	round_keys []u32
	rounds     int
}

// Cipher.new expands a 16, 24 or 32 byte key.
pub fn Cipher.new(key []u8) !&Cipher {
	rounds := match key.len {
		16 { 10 }
		24 { 12 }
		32 { 14 }
		else { return error('aes: a key must be 16, 24 or 32 bytes, got ${key.len}') }
	}
	return &Cipher{
		round_keys: expand_key(key, rounds)
		rounds:     rounds
	}
}

// key_size is the length of the key this cipher was built from.
@[inline]
pub fn (c &Cipher) key_size() int {
	return (c.rounds - 6) * 4
}

// encrypt_block encrypts exactly one block from src into dst.
//
// dst and src may be the same slice. Anything shorter than a block is a
// programming error rather than a runtime condition, so it is an error return
// and not a panic - this library never panics on data it was handed.
pub fn (c &Cipher) encrypt_block(mut dst []u8, src []u8) ! {
	if src.len < block_size || dst.len < block_size {
		return error('aes: encrypt_block needs a full ${block_size}-byte block')
	}
	s0, s1, s2, s3 := c.encrypt_words(load_u32(src, 0), load_u32(src, 4), load_u32(src, 8),
		load_u32(src, 12))
	store_u32(mut dst, 0, s0)
	store_u32(mut dst, 4, s1)
	store_u32(mut dst, 8, s2)
	store_u32(mut dst, 12, s3)
}