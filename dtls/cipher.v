module dtls

import webrtc.internal.aes
import webrtc.internal.codec

// AEAD record protection for TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
// (RFC 5288, as applied to DTLS by RFC 6347).
//
// The nonce is split: four bytes come from the key block and never appear on
// the wire, and eight are sent with each record. Since a repeated nonce under
// the same key destroys GCM completely, the explicit half is the record's
// epoch and sequence number rather than a counter of our own - those are
// already unique per record and are already in the header.

// gcm_key_length is the AES-128 key size.
const gcm_key_length = 16

// gcm_fixed_iv_length is the part of the nonce taken from the key block.
const gcm_fixed_iv_length = 4

// gcm_explicit_nonce_length is the part sent with each record.
const gcm_explicit_nonce_length = 8

// gcm_tag_length is the authentication tag size.
const gcm_tag_length = 16

// gcm_key_block_length is what the PRF must produce: two keys and two fixed
// IVs. There are no MAC keys, because the AEAD authenticates.
const gcm_key_block_length = 2 * gcm_key_length + 2 * gcm_fixed_iv_length

// CipherError is returned when a record cannot be protected or unprotected.
pub struct CipherError {
pub:
	detail string
	// authentication distinguishes a forged or corrupted record from a
	// programming error. A caller should count the former and investigate the
	// latter.
	authentication bool
}