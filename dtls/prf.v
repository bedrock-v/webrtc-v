// Package dtls implements DTLS 1.2 (RFC 6347) and the DTLS-SRTP profile
// (RFC 5764) that WebRTC uses to key its media.
//
// The handshake is what turns an ICE path into a secure one: it authenticates
// the peer against the certificate fingerprint carried in the SDP, and it
// produces the keying material the srtp package needs.
module dtls

import crypto.hmac
import crypto.sha256

// The TLS 1.2 pseudorandom function (RFC 5246 section 5).
//
// P_hash is an expanding HMAC chain, and PRF is P_hash over the label
// concatenated with the seed. TLS 1.2 fixes the hash at whatever the cipher
// suite's PRF hash is; every suite this implementation offers uses SHA-256, so
// that is the only one here. Adding another would mean parameterising the hash,
// not adding a second copy of this.

// prf_label_master_secret derives the master secret from the pre-master secret.
const prf_label_master_secret = 'master secret'

// prf_label_extended_master_secret derives it from the handshake transcript
// instead (RFC 7627), which binds the secret to the handshake that produced it.
const prf_label_extended_master_secret = 'extended master secret'

// prf_label_key_expansion derives the record protection keys.
const prf_label_key_expansion = 'key expansion'

// prf_label_client_finished and prf_label_server_finished derive the verify
// data that proves each side saw the same handshake.
const prf_label_client_finished = 'client finished'
const prf_label_server_finished = 'server finished'

// prf_label_dtls_srtp is the RFC 5764 exporter label. The keying material for
// SRTP comes out of the same PRF as everything else, under a label reserved for
// it, so that it is cryptographically separated from the record keys.
const prf_label_dtls_srtp = 'EXTRACTOR-dtls_srtp'

// master_secret_length is fixed at 48 bytes by TLS 1.2.
const master_secret_length = 48

// verify_data_length is 12 bytes for every suite in TLS 1.2.
const verify_data_length = 12

// p_hash expands a secret into length bytes (RFC 5246 section 5).
//
//	A(0) = seed
//	A(i) = HMAC(secret, A(i-1))
//	P_hash = HMAC(secret, A(1) + seed) + HMAC(secret, A(2) + seed) + ...
fn p_hash(secret []u8, seed []u8, length int) []u8 {
	mut out := []u8{cap: length}
	mut a := seed.clone()
	for out.len < length {
		a = hmac.new(secret, a, sha256.sum, sha256.block_size)
		mut block_input := []u8{cap: a.len + seed.len}
		block_input << a
		block_input << seed
		out << hmac.new(secret, block_input, sha256.sum, sha256.block_size)
	}
	return out[..length]
}

// prf computes PRF(secret, label, seed) truncated to length bytes.
fn prf(secret []u8, label string, seed []u8, length int) []u8 {
	mut labelled := []u8{cap: label.len + seed.len}
	labelled << label.bytes()
	labelled << seed
	return p_hash(secret, labelled, length)
}

// master_secret derives the master secret from the pre-master secret and the
// two handshake randoms (RFC 5246 section 8.1).
pub fn master_secret(pre_master_secret []u8, client_random []u8, server_random []u8) []u8 {
	mut seed := []u8{cap: client_random.len + server_random.len}
	seed << client_random
	seed << server_random
	return prf(pre_master_secret, prf_label_master_secret, seed, master_secret_length)
}

// extended_master_secret derives the master secret from the handshake
// transcript instead of the randoms (RFC 7627).
//
// This is what closes the triple-handshake attack: binding the secret to a hash
// of the handshake means two sessions cannot be made to share a master secret
// by replaying the randoms into a third connection.
pub fn extended_master_secret(pre_master_secret []u8, handshake_hash []u8) []u8 {
	return prf(pre_master_secret, prf_label_extended_master_secret, handshake_hash,
		master_secret_length)
}

// key_block expands the master secret into the record protection keys.
//
// Note the seed order: server random first, then client. It is the opposite of
// the master secret derivation, and getting it backwards produces two peers
// that complete a handshake and then cannot decrypt each other.
pub fn key_block(master []u8, client_random []u8, server_random []u8, length int) []u8 {
	mut seed := []u8{cap: server_random.len + client_random.len}
	seed << server_random
	seed << client_random
	return prf(master, prf_label_key_expansion, seed, length)
}