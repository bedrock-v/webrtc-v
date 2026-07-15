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

// RecordCipher.new returns a cipher for one direction's keys.
pub fn RecordCipher.new(keys RecordKeys) !RecordCipher {
	if keys.key.len != gcm_key_length {
		return CipherError{
			detail: 'AES-128-GCM needs a ${gcm_key_length}-byte key, got ${keys.key.len}'
		}
	}
	if keys.fixed_iv.len != gcm_fixed_iv_length {
		return CipherError{
			detail: 'AES-128-GCM needs a ${gcm_fixed_iv_length}-byte fixed IV, got ${keys.fixed_iv.len}'
		}
	}
	gcm := aes.Gcm.new(keys.key) or {
		return CipherError{
			detail: 'initialising AES-GCM: ${err.msg()}'
		}
	}
	return RecordCipher{
		keys: keys
		gcm:  gcm
	}
}

// nonce builds the 12-byte GCM nonce for a record: the fixed IV followed by the
// explicit part.
fn (c &RecordCipher) nonce(explicit []u8) []u8 {
	mut out := []u8{cap: gcm_fixed_iv_length + gcm_explicit_nonce_length}
	out << c.keys.fixed_iv
	out << explicit
	return out
}

// explicit_nonce_for returns the eight bytes sent with a record: the epoch and
// sequence number, which are unique per record by construction.
fn explicit_nonce_for(epoch u16, sequence_number u64) []u8 {
	mut w := codec.Writer.with_capacity(gcm_explicit_nonce_length)
	w.u16(epoch)
	w.u48(sequence_number)
	return w.buf
}

// additional_data builds the AEAD associated data (RFC 5246 section 6.2.3.3,
// with the DTLS substitution from RFC 6347 section 4.1.2.1).
//
// It is the record header with the epoch and sequence number standing in for
// TLS's implicit sequence number, and with the length being that of the
// plaintext rather than of the record. Because the header is authenticated but
// not encrypted, an attacker who rewrites the epoch, the sequence number or the
// content type makes the tag fail.
fn additional_data(epoch u16, sequence_number u64, content_type ContentType, version ProtocolVersion, plaintext_length int) []u8 {
	mut w := codec.Writer.with_capacity(13)
	w.u16(epoch)
	w.u48(sequence_number)
	w.u8(u8(content_type))
	w.u16(u16(version))
	w.u16(u16(plaintext_length))
	return w.buf
}

// protect encrypts a record payload, returning the fragment to put on the wire:
// the explicit nonce, the ciphertext and the tag.
pub fn (mut c RecordCipher) protect(epoch u16, sequence_number u64, content_type ContentType, version ProtocolVersion, plaintext []u8) ![]u8 {
	explicit := explicit_nonce_for(epoch, sequence_number)
	aad := additional_data(epoch, sequence_number, content_type, version, plaintext.len)

	sealed := c.gcm.seal(plaintext, c.nonce(explicit), aad) or {
		return CipherError{
			detail: 'encrypting a record: ${err.msg()}'
		}
	}

	mut out := []u8{cap: explicit.len + sealed.len}
	out << explicit
	out << sealed
	return out
}

// unprotect verifies and decrypts a record fragment.
//
// The explicit nonce carried in the record is used rather than the header's
// epoch and sequence number, even though a conforming sender makes them equal.
// A peer is entitled to choose its explicit nonce freely, and the header is
// authenticated separately through the associated data, so trusting the record
// here costs nothing and interoperates with senders that do something else.
pub fn (mut c RecordCipher) unprotect(epoch u16, sequence_number u64, content_type ContentType, version ProtocolVersion, fragment []u8) ![]u8 {
	minimum := gcm_explicit_nonce_length + gcm_tag_length
	if fragment.len < minimum {
		return CipherError{
			detail: 'record fragment of ${fragment.len} bytes is smaller than the ${minimum}-byte minimum'
		}
	}
	explicit := fragment[..gcm_explicit_nonce_length]
	sealed := fragment[gcm_explicit_nonce_length..]
	plaintext_length := sealed.len - gcm_tag_length
	aad := additional_data(epoch, sequence_number, content_type, version, plaintext_length)

	plaintext := c.gcm.open(sealed, c.nonce(explicit), aad) or {
		return CipherError{
			detail:         'record did not authenticate'
			authentication: true
		}
	}
	return plaintext
}

// overhead is how many bytes protection adds to a payload, which a caller needs
// in order to fragment a handshake message to fit the path MTU.
@[inline]
pub fn (c &RecordCipher) overhead() int {
	return gcm_explicit_nonce_length + gcm_tag_length
}
