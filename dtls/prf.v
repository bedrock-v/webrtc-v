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