// Package dtls implements DTLS 1.2 (RFC 6347) and the DTLS-SRTP profile
// (RFC 5764) that WebRTC uses to key its media.
//
// The handshake is what turns an ICE path into a secure one: it authenticates
// the peer against the certificate fingerprint carried in the SDP, and it
// produces the keying material the srtp package needs.
module dtls

import crypto.hmac
import crypto.sha256