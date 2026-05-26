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