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