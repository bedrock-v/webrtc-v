module srtp

import encoding.hex

// RFC 3711 appendix B.3 key derivation test vector.
const kdf_master_key = 'e1f97a0d3e018be0d64fa32c06de4139'
const kdf_master_salt = '0ec675ad498afeebb6960b3aabe6'
const kdf_expected_cipher_key = 'c61e7a93744f39ee10734afe3ff7a087'
const kdf_expected_cipher_salt = '30cbbc08863d8c85d49db34a9ae1'
const kdf_expected_auth_key = 'cebe321f6ff7716b6fd4ab49af256a156d38baa4'

fn test_rfc3711_key_derivation() {
	master_key := hex.decode(kdf_master_key)!
	master_salt := hex.decode(kdf_master_salt)!

	cipher_key := derive_key(master_key, master_salt, label_srtp_encryption, 16)!
	assert cipher_key.hex() == kdf_expected_cipher_key

	cipher_salt := derive_key(master_key, master_salt, label_srtp_salt, 14)!
	assert cipher_salt.hex() == kdf_expected_cipher_salt

	auth_key := derive_key(master_key, master_salt, label_srtp_auth, 20)!
	assert auth_key.hex() == kdf_expected_auth_key
}

fn test_derived_keys_differ_per_label() {
	master_key := hex.decode(kdf_master_key)!
	master_salt := hex.decode(kdf_master_salt)!
	keys := derive_session_keys(master_key, master_salt, .aes128_cm_hmac_sha1_80)!

	// Each label must produce a distinct key: sharing one between RTP and RTCP,
	// or between encryption and authentication, would let a weakness in one use
	// compromise the other.
	all := [keys.rtp_key.hex(), keys.rtp_salt.hex(), keys.rtp_auth.hex(),
		keys.rtcp_key.hex(), keys.rtcp_salt.hex(), keys.rtcp_auth.hex()]
	mut seen := map[string]bool{}
	for k in all {
		assert k !in seen, 'two derived keys are identical'
		seen[k] = true
	}
}

fn test_aead_profile_derives_no_auth_key() {
	master_key := []u8{len: 16, init: u8(index)}
	master_salt := []u8{len: 12, init: u8(index)}
	keys := derive_session_keys(master_key, master_salt, .aead_aes_128_gcm)!
	// GCM authenticates with the key it encrypts with, so a separate
	// authentication key would be an unused secret.
	assert keys.rtp_auth.len == 0
	assert keys.rtcp_auth.len == 0
}

fn test_derive_rejects_wrong_key_sizes() {
	derive_session_keys([]u8{len: 15}, []u8{len: 14}, .aes128_cm_hmac_sha1_80) or {
		derive_session_keys([]u8{len: 16}, []u8{len: 13}, .aes128_cm_hmac_sha1_80) or {
			derive_session_keys([]u8{len: 16}, []u8{len: 12}, .aead_aes_256_gcm) or { return }
			assert false, 'a 16-byte key must be rejected for the 256-bit profile'
		}
		assert false, 'a short salt must be rejected'
	}
	assert false, 'a short key must be rejected'
}

fn test_profile_parameters() {
	assert profile_from_value(0x0001)? == Profile.aes128_cm_hmac_sha1_80
	assert profile_from_value(0x0008)? == Profile.aead_aes_256_gcm
	assert profile_from_value(0x1234) == none

	assert Profile.aes128_cm_hmac_sha1_80.rtp_auth_tag_len() == 10
	assert Profile.aes128_cm_hmac_sha1_32.rtp_auth_tag_len() == 4
	// RFC 3711 section 5.2 keeps SRTCP at an 80-bit tag even when SRTP is
	// truncated to 32.
	assert Profile.aes128_cm_hmac_sha1_32.rtcp_auth_tag_len() == 10
	assert Profile.aead_aes_256_gcm.master_key_len() == 32
	assert Profile.aead_aes_128_gcm.master_salt_len() == 12
	assert !Profile.aes128_cm_hmac_sha1_80.is_aead()
	assert Profile.aead_aes_128_gcm.is_aead()
}

fn test_split_keying_material_order() {
	// RFC 5764 section 4.2 orders the extractor output as both keys and then
	// both salts, not as key-salt pairs.
	profile := Profile.aes128_cm_hmac_sha1_80
	mut material := []u8{}
	material << []u8{len: 16, init: 0x11} // client key
	material << []u8{len: 16, init: 0x22} // server key
	material << []u8{len: 14, init: 0x33} // client salt
	material << []u8{len: 14, init: 0x44} // server salt

	client, server := split_keying_material(material, profile)!
	assert client.key.all(it == 0x11)
	assert server.key.all(it == 0x22)
	assert client.salt.all(it == 0x33)
	assert server.salt.all(it == 0x44)

	split_keying_material(material[..10], profile) or { return }
	assert false, 'short keying material must be rejected'
}

fn make_pair(profile Profile) !(&Context, &Context) {
	key_len := profile.master_key_len()
	salt_len := profile.master_salt_len()
	key := []u8{len: key_len, init: u8(index * 3 + 1)}
	salt := []u8{len: salt_len, init: u8(index * 5 + 2)}
	sender := Context.new(key, salt, profile)!
	receiver := Context.new(key, salt, profile)!
	return sender, receiver
}

fn make_rtp(sequence u16, ssrc u32, payload []u8) []u8 {
	mut packet := [u8(0x80), 0x60, u8(sequence >> 8), u8(sequence), 0x00, 0x00, 0x00, 0x01,
		u8(ssrc >> 24), u8(ssrc >> 16), u8(ssrc >> 8), u8(ssrc)]
	packet << payload
	return packet
}

fn make_rtcp(ssrc u32) []u8 {
	// A receiver report with no report blocks: header, then the sender's SSRC.
	return [u8(0x80), 201, 0x00, 0x01, u8(ssrc >> 24), u8(ssrc >> 16), u8(ssrc >> 8), u8(ssrc)]
}

fn all_profiles() []Profile {
	return [Profile.aes128_cm_hmac_sha1_80, .aes128_cm_hmac_sha1_32, .aead_aes_128_gcm,
		.aead_aes_256_gcm]
}

fn test_rtp_round_trip_every_profile() {
	for profile in all_profiles() {
		mut sender, mut receiver := make_pair(profile)!
		payload := [u8(0xDE), 0xAD, 0xBE, 0xEF, 0x01, 0x02]
		plain := make_rtp(1000, 0xCAFEBABE, payload)

		protected := sender.protect_rtp(plain)!
		// The header is authenticated but not encrypted, so it stays readable.
		assert protected[..12] == plain[..12]
		// The payload must not appear in the clear.
		assert protected[12..12 + payload.len] != payload
		assert protected.len == plain.len + profile.rtp_auth_tag_len()

		recovered := receiver.unprotect_rtp(protected)!
		assert recovered == plain, 'round trip failed for ${profile}'
	}
}