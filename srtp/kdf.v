module srtp

import webrtc.internal.aes

// Key derivation labels from RFC 3711 section 4.3.1. Each derived key comes
// from the same master key under a different label, so that compromising one
// session key does not reveal the others.
const label_srtp_encryption = u8(0x00)
const label_srtp_auth = u8(0x01)
const label_srtp_salt = u8(0x02)
const label_srtcp_encryption = u8(0x03)
const label_srtcp_auth = u8(0x04)
const label_srtcp_salt = u8(0x05)

// aes_block_size is the AES block size in bytes.
const aes_block_size = 16

// derive_key produces a session key from a master key and salt.
//
// The construction is the AES-CM PRF of RFC 3711 section 4.3.3: the label is
// XORed into the salt, the result becomes the counter block, and the AES
// keystream from it is the derived key.
//
// The key derivation rate is fixed at zero, meaning keys are derived once per
// session rather than periodically re-derived. That is what WebRTC does; a
// non-zero rate would need the packet index folded into the block below.
fn derive_key(master_key []u8, master_salt []u8, label u8, length int) ![]u8 {
	if master_salt.len > aes_block_size - 2 {
		return error('srtp: master salt of ${master_salt.len} bytes is too long for the KDF block')
	}
	if length < 0 {
		return error('srtp: negative derived key length')
	}

	// x = master_salt XOR (label || 0), left-aligned in the block, with the low
	// two bytes reserved for the counter.
	mut block := []u8{len: aes_block_size}
	for i, b in master_salt {
		block[i] = b
	}
	// The label sits seven bytes from the end of the salt, because key_id is
	// label || index_div_kdr and index_div_kdr is 48 bits wide.
	label_offset := master_salt.len - 7
	if label_offset < 0 {
		return error('srtp: master salt of ${master_salt.len} bytes is too short for the KDF')
	}
	block[label_offset] ^= label

	return aes_keystream(master_key, block, length)!
}

// aes_keystream returns the first length bytes of the AES counter-mode
// keystream starting from the given counter block.
fn aes_keystream(key []u8, counter_block []u8, length int) ![]u8 {
	if counter_block.len != aes_block_size {
		return error('srtp: counter block must be ${aes_block_size} bytes, got ${counter_block.len}')
	}
	block := aes.Cipher.new(key)!
	mut ctr := aes.Ctr.new(block, counter_block)!

	// Counter mode is a stream cipher: XORing zeros yields the keystream.
	mut out := []u8{len: length}
	src := []u8{len: length}
	ctr.xor_key_stream(mut out, src)!
	return out
}

// SessionKeys holds every key derived from one master key.
struct SessionKeys {
	rtp_key   []u8
	rtp_salt  []u8
	rtp_auth  []u8
	rtcp_key  []u8
	rtcp_salt []u8
	rtcp_auth []u8
}

// derive_session_keys expands a master key and salt into the six session keys.
//
// The AEAD profiles derive no authentication key: GCM authenticates with the
// same key it encrypts with, so asking for one would produce an unused secret.
fn derive_session_keys(master_key []u8, master_salt []u8, profile Profile) !SessionKeys {
	if master_key.len != profile.master_key_len() {
		return error('srtp: ${profile} needs a ${profile.master_key_len()}-byte master key, got ${master_key.len}')
	}
	if master_salt.len != profile.master_salt_len() {
		return error('srtp: ${profile} needs a ${profile.master_salt_len()}-byte master salt, got ${master_salt.len}')
	}

	key_len := profile.master_key_len()
	salt_len := profile.master_salt_len()
	auth_len := profile.auth_key_len()

	return SessionKeys{
		rtp_key:   derive_key(master_key, master_salt, label_srtp_encryption, key_len)!
		rtp_salt:  derive_key(master_key, master_salt, label_srtp_salt, salt_len)!
		rtp_auth:  if auth_len > 0 {
			derive_key(master_key, master_salt, label_srtp_auth, auth_len)!
		} else {
			[]u8{}
		}
		rtcp_key:  derive_key(master_key, master_salt, label_srtcp_encryption, key_len)!
		rtcp_salt: derive_key(master_key, master_salt, label_srtcp_salt, salt_len)!
		rtcp_auth: if auth_len > 0 {
			derive_key(master_key, master_salt, label_srtcp_auth, auth_len)!
		} else {
			[]u8{}
		}
	}
}

// counter_mode_iv builds the AES-CM counter block for one packet
// (RFC 3711 section 4.1.1).
//
//	IV = (salt * 2^16) XOR (SSRC * 2^64) XOR (index * 2^16)
//
// Laid out over the 16-byte block that means the salt occupies bytes 0-13, the
// SSRC is XORed into bytes 4-7, the 48-bit index into bytes 8-13, and the last
// two bytes are the block counter. The index is what makes every packet's
// keystream distinct; reusing one with the same key is a total break of
// confidentiality, which is why the index is derived from the roll-over count
// rather than from the sequence number alone.
fn counter_mode_iv(salt []u8, ssrc u32, index u64) []u8 {
	mut iv := []u8{len: aes_block_size}
	for i, b in salt {
		if i >= aes_block_size {
			break
		}
		iv[i] = b
	}
	iv[4] ^= u8(ssrc >> 24)
	iv[5] ^= u8(ssrc >> 16)
	iv[6] ^= u8(ssrc >> 8)
	iv[7] ^= u8(ssrc)
	iv[8] ^= u8(index >> 40)
	iv[9] ^= u8(index >> 32)
	iv[10] ^= u8(index >> 24)
	iv[11] ^= u8(index >> 16)
	iv[12] ^= u8(index >> 8)
	iv[13] ^= u8(index)
	return iv
}