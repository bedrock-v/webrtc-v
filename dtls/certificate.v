module dtls

import crypto.ecdsa
import crypto.sha1
import crypto.sha256
import crypto.sha512
import time
import webrtc.internal.randutil

// Certificate generation and fingerprinting.
//
// WebRTC does not use a certificate authority. Each endpoint generates a
// self-signed certificate, publishes its fingerprint in the SDP, and the
// handshake is authenticated by checking that the certificate the peer
// presented hashes to the fingerprint that was signalled (RFC 8122). The chain
// of trust runs through the signalling channel, not through a CA, which is why
// none of the usual path validation appears here - and why the fingerprint
// check is not optional.

// Object identifiers used in the certificates this package produces.
const oid_ec_public_key = '1.2.840.10045.2.1'
const oid_prime256v1 = '1.2.840.10045.3.1.7'
const oid_ecdsa_with_sha256 = '1.2.840.10045.4.3.2'
const oid_common_name = '2.5.4.3'

// default_certificate_lifetime is how long a generated certificate is valid.
//
// Thirty days is far longer than any call and short enough that a leaked key
// stops being useful. The value matters less than it would with a CA, because
// the fingerprint in the SDP is what actually authenticates the peer.
pub const default_certificate_lifetime = 30 * 24 * time.hour

// HashAlgorithm is a certificate fingerprint hash. RFC 8122 registers several;
// SHA-256 is what every browser signals.
pub enum HashAlgorithm {
	sha1
	sha256
	sha384
	sha512
}

pub fn (h HashAlgorithm) str() string {
	return match h {
		.sha1 { 'sha-1' }
		.sha256 { 'sha-256' }
		.sha384 { 'sha-384' }
		.sha512 { 'sha-512' }
	}
}