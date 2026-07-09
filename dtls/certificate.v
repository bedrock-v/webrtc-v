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