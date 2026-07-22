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