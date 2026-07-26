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

// select_parameters is the server's half of the negotiation: it checks the
// client offered something we can use and records what was chosen.
fn (mut c Conn) select_parameters(hello ClientHello) ! {
	if CipherSuite.ecdhe_ecdsa_with_aes_128_gcm_sha256 !in hello.cipher_suites {
		c.send_alert(alert_handshake_failure)
		return ConnError{
			reason: .handshake_failure
			detail: 'the client offered no cipher suite we implement'
		}
	}
	if extension := find_extension(hello.extensions, ext_supported_groups) {
		if extension is SupportedGroups {
			if NamedCurve.secp256r1 !in extension.curves {
				c.send_alert(alert_handshake_failure)
				return ConnError{
					reason: .handshake_failure
					detail: 'the client does not support secp256r1'
				}
			}
		}
	}

	// Extended master secret is used only when both sides ask for it.
	c.use_extended_master = find_extension(hello.extensions, ext_extended_master_secret) != none

	if c.config.srtp_profiles.len > 0 {
		if extension := find_extension(hello.extensions, ext_use_srtp) {
			if extension is UseSrtp {
				// The choice is made from our preference order, not theirs: a
				// peer listing a weaker profile first must not be able to talk
				// us into it.
				c.negotiated_srtp_profile = negotiate_srtp_profile(extension.profiles,
					c.config.srtp_profiles)
				if c.negotiated_srtp_profile == none {
					c.send_alert(alert_handshake_failure)
					return ConnError{
						reason: .no_srtp_profile
						detail: 'no SRTP protection profile in common'
					}
				}
			}
		}
	}
}

// build_server_hello assembles our answer.
fn (mut c Conn) build_server_hello() !ServerHello {
	mut extensions := [
		Extension(SupportedEcPointFormats{
			formats: [EcPointFormat.uncompressed]
		}),
		Extension(RenegotiationInfo{}),
	]
	if c.use_extended_master {
		extensions << ExtendedMasterSecret{}
	}
	if profile := c.negotiated_srtp_profile {
		extensions << UseSrtp{
			profiles: [profile]
		}
	}
	return ServerHello{
		version:      .dtls_1_2
		random:       c.local_random
		cipher_suite: .ecdhe_ecdsa_with_aes_128_gcm_sha256
		extensions:   extensions
	}
}

// build_server_key_exchange signs our ephemeral public key.
//
// The signature covers both randoms as well as the key. Without the randoms it
// could be lifted from one handshake into another; without the signature,
// anyone on the path could substitute their own key and read everything.
fn (mut c Conn) build_server_key_exchange() !ServerKeyExchange {
	point := c.local_ecdh_point()!
	signed := c.key_exchange_signature_input(point)

	signature := c.local_certificate.private_key.sign(signed) or {
		return ConnError{
			reason: .handshake_failure
			detail: 'signing the key exchange: ${err.msg()}'
		}
	}
	return ServerKeyExchange{
		curve:      .secp256r1
		public_key: point
		signature:  signature
	}
}

// key_exchange_signature_input builds the bytes a ServerKeyExchange signature
// covers: client random, server random, then the ECDH parameters.
//
// The client and server randoms go in the order RFC 4492 section 5.4 gives, not
// in local-then-remote order, so it is built from the connection's role rather
// than from whichever side is calling.
fn (c &Conn) key_exchange_signature_input(point []u8) []u8 {
	client_random, server_random := c.client_and_server_randoms()
	mut out := []u8{cap: 2 * random_size + 4 + point.len}
	out << client_random
	out << server_random
	out << server_ecdh_params(.secp256r1, point)
	return out
}

// build_certificate_verify proves we hold the key for the certificate we sent,
// by signing everything exchanged so far.
fn (mut c Conn) build_certificate_verify() !CertificateVerify {
	signature := c.local_certificate.private_key.sign(c.transcript) or {
		return ConnError{
			reason: .handshake_failure
			detail: 'signing the handshake transcript: ${err.msg()}'
		}
	}
	return CertificateVerify{
		signature: signature
	}
}

// apply_server_message folds one message of the server's flight into our state,
// returning true when the flight is complete.
fn (mut c Conn) apply_server_message(message HandshakeMessage) !bool {
	match message {
		ServerHello {
			c.remote_random = message.random
			c.use_extended_master = find_extension(message.extensions, ext_extended_master_secret) != none
			if extension := find_extension(message.extensions, ext_use_srtp) {
				if extension is UseSrtp {
					if extension.profiles.len != 1 {
						return ConnError{
							reason: .no_srtp_profile
							detail: 'the server selected ${extension.profiles.len} SRTP profiles, expected exactly 1'
						}
					}
					chosen := extension.profiles[0]
					// A server may only select from what we offered. Accepting
					// anything else would let it choose a profile we rejected.
					if chosen !in c.config.srtp_profiles {
						c.send_alert(alert_illegal_parameter)
						return ConnError{
							reason: .no_srtp_profile
							detail: 'the server selected ${chosen}, which we did not offer'
						}
					}
					c.negotiated_srtp_profile = chosen
				}
			} else if c.config.srtp_profiles.len > 0 {
				c.log.warn('the server did not select an SRTP profile; media cannot be keyed')
			}
		}
		CertificateMessage {
			c.accept_peer_certificate(message)!
		}
		ServerKeyExchange {
			c.accept_server_key_exchange(message)!
		}
		CertificateRequest {
			// Mutual authentication is what WebRTC always does, and this
			// implementation always sends its certificate, so there is nothing
			// to record.
		}
		ServerHelloDone {
			return true
		}
		else {
			return ConnError{
				reason: .handshake_failure
				detail: 'unexpected ${message.handshake_type()} from the server'
			}
		}
	}
	return false
}

// apply_client_message folds one message of the client's flight into our state.
fn (mut c Conn) apply_client_message(message HandshakeMessage) ! {
	match message {
		CertificateMessage {
			c.accept_peer_certificate(message)!
		}
		ClientKeyExchange {
			c.peer_ecdh = parse_peer_point(message.public_key) or {
				c.send_alert(alert_illegal_parameter)
				return ConnError{
					reason: .handshake_failure
					detail: 'the client key share is not a valid P-256 point'
				}
			}
			// Derive here, not later: RFC 7627's session hash covers the
			// handshake up to and including this message, and collect_handshake
			// has just appended it. Waiting until the ChangeCipherSpec would
			// hash the CertificateVerify in as well, and the client would have
			// computed something different.
			c.derive_secrets()!
		}
		CertificateVerify {
			c.verify_certificate_verify(message)!
		}
		else {
			return ConnError{
				reason: .handshake_failure
				detail: 'unexpected ${message.handshake_type()} from the client'
			}
		}
	}
}

// accept_peer_certificate parses the peer's certificate and checks it against
// the fingerprints the signalling channel carried.
//
// This is the whole of peer authentication in WebRTC. There is no CA and no
// name to check; the certificate is trusted precisely because its fingerprint
// matches one that arrived over a channel the application already trusts. If
// this check does not happen, nothing authenticates the peer at all.
fn (mut c Conn) accept_peer_certificate(message CertificateMessage) ! {
	if message.certificates.len == 0 {
		c.send_alert(alert_bad_certificate)
		return ConnError{
			reason: .bad_certificate
			detail: 'the peer sent an empty certificate chain'
		}
	}
	// The end-entity certificate is first. Any others would be issuers, which
	// are meaningless without a CA.
	parsed := parse_certificate(message.certificates[0]) or {
		c.send_alert(alert_bad_certificate)
		return ConnError{
			reason: .bad_certificate
			detail: 'the peer certificate did not parse: ${err.msg()}'
		}
	}
	c.remote_certificate = parsed

	if c.config.insecure_skip_fingerprint_verification {
		c.log.warn('accepting the peer certificate without checking its fingerprint')
		return
	}

	for expected in c.config.remote_fingerprints {
		if fingerprint_of(parsed.der, expected.algorithm).matches(expected) {
			c.log.debug('peer certificate matches the signalled ${expected.algorithm} fingerprint')
			return
		}
	}

	c.send_alert(alert_certificate_unknown)
	return ConnError{
		reason: .fingerprint_mismatch
		detail: 'the peer certificate matches none of the ${c.config.remote_fingerprints.len} signalled fingerprints'
	}
}

// accept_server_key_exchange checks the signature over the server's key share
// and records the share.
fn (mut c Conn) accept_server_key_exchange(message ServerKeyExchange) ! {
	if message.curve != .secp256r1 {
		c.send_alert(alert_illegal_parameter)
		return ConnError{
			reason: .handshake_failure
			detail: 'the server chose curve ${message.curve}; only secp256r1 is supported'
		}
	}
	certificate := c.remote_certificate or {
		return ConnError{
			reason: .handshake_failure
			detail: 'a ServerKeyExchange arrived before the certificate that would verify it'
		}
	}

	signed := c.key_exchange_signature_input(message.public_key)
	ok := certificate.public_key.verify(signed, message.signature) or {
		c.send_alert(alert_decrypt_error)
		return ConnError{
			reason: .bad_signature
			detail: 'verifying the key exchange signature: ${err.msg()}'
		}
	}
	if !ok {
		c.send_alert(alert_decrypt_error)
		return ConnError{
			reason: .bad_signature
			detail: 'the key exchange signature did not verify'
		}
	}

	c.peer_ecdh = parse_peer_point(message.public_key) or {
		c.send_alert(alert_illegal_parameter)
		return ConnError{
			reason: .handshake_failure
			detail: 'the server key share is not a valid P-256 point'
		}
	}
}

// verify_certificate_verify checks that the peer signed the transcript with the
// key belonging to the certificate it sent.
fn (mut c Conn) verify_certificate_verify(message CertificateVerify) ! {
	certificate := c.remote_certificate or {
		return ConnError{
			reason: .handshake_failure
			detail: 'a CertificateVerify arrived before the certificate that would verify it'
		}
	}

	ok := certificate.public_key.verify(c.transcript_at_certificate_verify, message.signature) or {
		c.send_alert(alert_decrypt_error)
		return ConnError{
			reason: .bad_signature
			detail: 'verifying the CertificateVerify: ${err.msg()}'
		}
	}
	if !ok {
		c.send_alert(alert_decrypt_error)
		return ConnError{
			reason: .bad_signature
			detail: 'the CertificateVerify did not verify; the peer does not hold the key for its certificate'
		}
	}
}

// parse_peer_point decodes an uncompressed P-256 point.
//
// OpenSSL validates that the point is on the curve, which is what stops an
// invalid-curve attack: a point on a different, weaker curve would let the peer
// recover our private key from a handful of handshakes.
fn parse_peer_point(point []u8) ?ecdsa.PublicKey {
	return ecdsa.PublicKey.from_uncompressed_bytes(point, nid: .prime256v1) or { none }
}