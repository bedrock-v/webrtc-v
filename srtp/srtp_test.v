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