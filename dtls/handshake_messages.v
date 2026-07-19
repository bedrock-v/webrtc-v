module dtls

import crypto.ecdsa
import webrtc.srtp

// Building and applying the individual handshake messages: the key exchange,
// the signatures that authenticate it, and the parameter negotiation.

// local_ecdh_point returns our ephemeral public key as an uncompressed point.
fn (c &Conn) local_ecdh_point() ![]u8 {
	point := c.ecdh_public.uncompressed_bytes() or {
		return ConnError{
			reason: .handshake_failure
			detail: 'encoding the ephemeral public key: ${err.msg()}'
		}
	}
	return point
}