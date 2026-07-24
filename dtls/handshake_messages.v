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

// build_client_hello assembles our offer. The cookie is empty on the first
// hello and echoes the server's HelloVerifyRequest on the second.
fn (mut c Conn) build_client_hello(cookie []u8) !ClientHello {
	mut extensions := [
		Extension(SupportedGroups{
			curves: [NamedCurve.secp256r1]
		}),
		Extension(SupportedEcPointFormats{
			formats: [EcPointFormat.uncompressed]
		}),
		Extension(SupportedSignatureAlgorithms{
			schemes: [ecdsa_sha256]
		}),
		// RFC 7627: bind the master secret to the handshake transcript.
		Extension(ExtendedMasterSecret{}),
		// RFC 5746: several stacks refuse a handshake that omits this even
		// though nothing here ever renegotiates.
		Extension(RenegotiationInfo{}),
	]
	if c.config.srtp_profiles.len > 0 {
		extensions << UseSrtp{
			profiles: c.config.srtp_profiles.clone()
		}
	}

	return ClientHello{
		version:       .dtls_1_2
		random:        c.local_random
		cookie:        cookie.clone()
		cipher_suites: [CipherSuite.ecdhe_ecdsa_with_aes_128_gcm_sha256]
		extensions:    extensions
	}
}