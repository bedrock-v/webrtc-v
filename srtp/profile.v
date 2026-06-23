// Package srtp implements the Secure Real-time Transport Protocol (RFC 3711)
// and its AES-GCM profiles (RFC 7714).
//
// SRTP is what makes WebRTC media confidential and authentic. The keys come
// from the DTLS handshake through the extractor of RFC 5764, so this package
// never negotiates anything: it takes keying material and turns RTP into SRTP
// and back.
//
// Two rules govern everything here. Authentication is verified before anything
// else is done with a packet, so a forged packet cannot reach the replay window
// or the decoder. And a packet that fails any check is dropped with an error
// rather than passed on partially processed.
module srtp

// Profile is an SRTP protection profile, identified by the values RFC 5764 and
// RFC 7714 register for the DTLS use_srtp extension.
pub enum Profile as u16 {
	// aes128_cm_hmac_sha1_80 is the profile every WebRTC endpoint supports.
	aes128_cm_hmac_sha1_80 = 0x0001
	// aes128_cm_hmac_sha1_32 trades authentication strength for four bytes per
	// packet. It is offered for interoperability; 32 bits of tag is weak enough
	// that it should not be preferred.
	aes128_cm_hmac_sha1_32 = 0x0002
	// aead_aes_128_gcm authenticates and encrypts in one pass and is what
	// modern endpoints negotiate.
	aead_aes_128_gcm = 0x0007
	// aead_aes_256_gcm is the 256-bit key variant.
	aead_aes_256_gcm = 0x0008
}

pub fn (p Profile) str() string {
	return match p {
		.aes128_cm_hmac_sha1_80 { 'SRTP_AES128_CM_HMAC_SHA1_80' }
		.aes128_cm_hmac_sha1_32 { 'SRTP_AES128_CM_HMAC_SHA1_32' }
		.aead_aes_128_gcm { 'SRTP_AEAD_AES_128_GCM' }
		.aead_aes_256_gcm { 'SRTP_AEAD_AES_256_GCM' }
	}
}

// profile_from_value maps a use_srtp extension value to a profile.
pub fn profile_from_value(v u16) ?Profile {
	return match v {
		0x0001 { Profile.aes128_cm_hmac_sha1_80 }
		0x0002 { Profile.aes128_cm_hmac_sha1_32 }
		0x0007 { Profile.aead_aes_128_gcm }
		0x0008 { Profile.aead_aes_256_gcm }
		else { none }
	}
}

// is_aead reports whether the profile authenticates through an AEAD rather than
// a separate HMAC.
@[inline]
pub fn (p Profile) is_aead() bool {
	return p == .aead_aes_128_gcm || p == .aead_aes_256_gcm
}

// master_key_len is the size of the master key the DTLS extractor must supply.
pub fn (p Profile) master_key_len() int {
	return match p {
		.aes128_cm_hmac_sha1_80, .aes128_cm_hmac_sha1_32, .aead_aes_128_gcm { 16 }
		.aead_aes_256_gcm { 32 }
	}
}

// master_salt_len is the size of the master salt.
//
// The counter-mode profiles use a 112-bit salt because the AES-CM construction
// leaves 16 bits of the block for the counter. The GCM profiles use 96 bits,
// which is the full nonce.
pub fn (p Profile) master_salt_len() int {
	return match p {
		.aes128_cm_hmac_sha1_80, .aes128_cm_hmac_sha1_32 { 14 }
		.aead_aes_128_gcm, .aead_aes_256_gcm { 12 }
	}
}

// auth_key_len is the size of the HMAC key, or zero for an AEAD profile.
pub fn (p Profile) auth_key_len() int {
	return match p {
		.aes128_cm_hmac_sha1_80, .aes128_cm_hmac_sha1_32 { 20 }
		.aead_aes_128_gcm, .aead_aes_256_gcm { 0 }
	}
}

// rtp_auth_tag_len is the number of tag bytes appended to an SRTP packet.
pub fn (p Profile) rtp_auth_tag_len() int {
	return match p {
		.aes128_cm_hmac_sha1_80 { 10 }
		.aes128_cm_hmac_sha1_32 { 4 }
		.aead_aes_128_gcm, .aead_aes_256_gcm { 16 }
	}
}

// rtcp_auth_tag_len is the number of tag bytes appended to an SRTCP packet.
//
// The 32-bit profile is an exception worth knowing about: RFC 3711 section 5.2
// keeps SRTCP at an 80-bit tag even when SRTP is truncated to 32, because
// control traffic is low volume and forging it is more damaging.
pub fn (p Profile) rtcp_auth_tag_len() int {
	return match p {
		.aes128_cm_hmac_sha1_80, .aes128_cm_hmac_sha1_32 { 10 }
		.aead_aes_128_gcm, .aead_aes_256_gcm { 16 }
	}
}

// keying_material_len is the number of bytes the DTLS extractor must produce
// for this profile: two keys and two salts.
pub fn (p Profile) keying_material_len() int {
	return 2 * (p.master_key_len() + p.master_salt_len())
}

// KeyingMaterial is one direction's master key and salt.
pub struct KeyingMaterial {
pub:
	key  []u8
	salt []u8
}