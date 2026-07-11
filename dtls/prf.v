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