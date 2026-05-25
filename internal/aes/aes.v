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

// encrypt_words is the round function, on the four state words.
//
// Everything hot lives here: the loop is unrolled by column rather than by
// round, each column is four table lookups and an exclusive-or, and the final
// round is peeled out because it uses the S-box directly instead of the tables.
@[direct_array_access]
fn (c &Cipher) encrypt_words(in0 u32, in1 u32, in2 u32, in3 u32) (u32, u32, u32, u32) {
	rk := c.round_keys
	mut s0 := in0 ^ rk[0]
	mut s1 := in1 ^ rk[1]
	mut s2 := in2 ^ rk[2]
	mut s3 := in3 ^ rk[3]

	mut offset := 4
	for _ in 1 .. c.rounds {
		t0 := te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >> 8) & 0xff] ^ te3[s3 & 0xff] ^ rk[offset]
		t1 := te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >> 8) & 0xff] ^ te3[s0 & 0xff] ^ rk[
			offset + 1]
		t2 := te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >> 8) & 0xff] ^ te3[s1 & 0xff] ^ rk[
			offset + 2]
		t3 := te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >> 8) & 0xff] ^ te3[s2 & 0xff] ^ rk[
			offset + 3]
		s0, s1, s2, s3 = t0, t1, t2, t3
		offset += 4
	}

	// The last round has no MixColumns, so the tables - which fold MixColumns
	// into the lookup - cannot be used.
	f0 := (u32(sbox[s0 >> 24]) << 24) | (u32(sbox[(s1 >> 16) & 0xff]) << 16) | (u32(sbox[(s2 >> 8) & 0xff]) << 8) | u32(sbox[s3 & 0xff])
	f1 := (u32(sbox[s1 >> 24]) << 24) | (u32(sbox[(s2 >> 16) & 0xff]) << 16) | (u32(sbox[(s3 >> 8) & 0xff]) << 8) | u32(sbox[s0 & 0xff])
	f2 := (u32(sbox[s2 >> 24]) << 24) | (u32(sbox[(s3 >> 16) & 0xff]) << 16) | (u32(sbox[(s0 >> 8) & 0xff]) << 8) | u32(sbox[s1 & 0xff])
	f3 := (u32(sbox[s3 >> 24]) << 24) | (u32(sbox[(s0 >> 16) & 0xff]) << 16) | (u32(sbox[(s1 >> 8) & 0xff]) << 8) | u32(sbox[s2 & 0xff])
	return f0 ^ rk[offset], f1 ^ rk[offset + 1], f2 ^ rk[offset + 2], f3 ^ rk[offset + 3]
}

// expand_key produces the round keys (FIPS-197 section 5.2).
@[direct_array_access]
fn expand_key(key []u8, rounds int) []u32 {
	words := key.len / 4
	total := 4 * (rounds + 1)
	mut rk := []u32{len: total}

	for i in 0 .. words {
		rk[i] = load_u32(key, i * 4)
	}
	for i in words .. total {
		mut temp := rk[i - 1]
		if i % words == 0 {
			temp = sub_word(rotate_word(temp)) ^ (u32(rcon[i / words]) << 24)
		} else if words > 6 && i % words == 4 {
			// AES-256 applies SubWord without the rotation on this step. Leaving
			// it out is a classic way to produce a key schedule that encrypts
			// fine and interoperates with nothing.
			temp = sub_word(temp)
		}
		rk[i] = rk[i - words] ^ temp
	}
	return rk
}

@[inline]
fn rotate_word(w u32) u32 {
	return (w << 8) | (w >> 24)
}

@[direct_array_access; inline]
fn sub_word(w u32) u32 {
	return (u32(sbox[(w >> 24) & 0xff]) << 24) | (u32(sbox[(w >> 16) & 0xff]) << 16) | (u32(sbox[(w >> 8) & 0xff]) << 8) | u32(sbox[w & 0xff])
}

@[direct_array_access; inline]
fn load_u32(b []u8, offset int) u32 {
	return (u32(b[offset]) << 24) | (u32(b[offset + 1]) << 16) | (u32(b[offset + 2]) << 8) | u32(b[
		offset + 3])
}

@[direct_array_access; inline]
fn store_u32(mut b []u8, offset int, v u32) {
	b[offset] = u8(v >> 24)
	b[offset + 1] = u8(v >> 16)
	b[offset + 2] = u8(v >> 8)
	b[offset + 3] = u8(v)
}

// rcon is the round constant, one per key schedule step.
const rcon = [u8(0x00), 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
	0xab, 0x4d]

// The S-box and the four round tables are derived at startup rather than
// written out as literals. It is a few microseconds once, it keeps 5 KB of
// magic numbers out of the source, and the derivation is the definition from
// FIPS-197 - which makes it checkable by reading rather than by trusting.
const sbox = build_sbox()

const te0 = build_table(0)
const te1 = build_table(1)
const te2 = build_table(2)
const te3 = build_table(3)

// build_sbox derives the S-box: the multiplicative inverse in GF(2^8) followed
// by the affine transformation of FIPS-197 section 5.1.1.
fn build_sbox() []u8 {
	// A log/antilog table over the generator 3 turns the inverse into a
	// subtraction, which avoids implementing the extended Euclidean algorithm.
	mut antilog := []u8{len: 256}
	mut log := []u8{len: 256}
	mut x := u8(1)
	for i in 0 .. 255 {
		antilog[i] = x
		log[x] = u8(i)
		x = xtime_multiply(x, 3)
	}

	mut out := []u8{len: 256}
	for i in 0 .. 256 {
		mut inverse := u8(0)
		if i != 0 {
			// The exponents run modulo 255, so an element whose logarithm is
			// zero - that is, one - inverts to itself rather than reading off
			// the end of the table.
			inverse = antilog[(255 - int(log[i])) % 255]
		}
		mut value := inverse
		mut result := inverse
		for _ in 0 .. 4 {
			value = (value << 1) | (value >> 7)
			result ^= value
		}
		out[i] = result ^ 0x63
	}
	return out
}

// build_table produces one of the four round tables. Each is the same set of
// values rotated by one byte, which is why the round function can index all
// four with the same S-box output.
fn build_table(rotation int) []u32 {
	// Built here rather than read from the `sbox` const: V does not promise an
	// initialisation order between consts, and a table silently derived from a
	// zeroed S-box would encrypt happily and interoperate with nothing.
	box := build_sbox()
	mut out := []u32{len: 256}
	for i in 0 .. 256 {
		s := box[i]
		// [s*2, s, s, s*3] is MixColumns applied to a single byte.
		word := (u32(xtime_multiply(s, 2)) << 24) | (u32(s) << 16) | (u32(s) << 8) | u32(xtime_multiply(s, 3))
		out[i] = rotate_right_bytes(word, rotation)
	}
	return out
}

@[inline]
fn rotate_right_bytes(w u32, count int) u32 {
	shift := u32(count * 8)
	if shift == 0 {
		return w
	}
	return (w >> shift) | (w << (32 - shift))
}