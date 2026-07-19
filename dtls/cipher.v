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

pub fn (e CipherError) msg() string {
	return 'dtls: ${e.detail}'
}

pub fn (e CipherError) code() int {
	return if e.authentication { 31 } else { 30 }
}

// RecordKeys is one direction's record protection state.
pub struct RecordKeys {
pub:
	key      []u8
	fixed_iv []u8
}

// KeySet is the pair of directions produced by one key block expansion.
pub struct KeySet {
pub:
	client RecordKeys
	server RecordKeys
}

// expand_key_block splits the PRF output into the four values RFC 5246
// section 6.3 defines, in the order it defines them.
//
// The order is client key, server key, client IV, server IV - both keys before
// either IV. Getting it wrong yields two endpoints that finish a handshake and
// then cannot decrypt each other, with no error that points at the cause.
pub fn expand_key_block(block []u8) !KeySet {
	if block.len < gcm_key_block_length {
		return CipherError{
			detail: 'key block is ${block.len} bytes, need ${gcm_key_block_length}'
		}
	}
	mut offset := 0
	client_key := block[offset..offset + gcm_key_length].clone()
	offset += gcm_key_length
	server_key := block[offset..offset + gcm_key_length].clone()
	offset += gcm_key_length
	client_iv := block[offset..offset + gcm_fixed_iv_length].clone()
	offset += gcm_fixed_iv_length
	server_iv := block[offset..offset + gcm_fixed_iv_length].clone()

	return KeySet{
		client: RecordKeys{
			key:      client_key
			fixed_iv: client_iv
		}
		server: RecordKeys{
			key:      server_key
			fixed_iv: server_iv
		}
	}
}

// RecordCipher protects records in one direction.
pub struct RecordCipher {
mut:
	keys RecordKeys
	// gcm is built once per direction rather than per record. Expanding the key
	// and the hash table costs about as much as encrypting a small record, so
	// doing it per record roughly halved throughput.
	gcm &aes.Gcm = unsafe { nil }
}