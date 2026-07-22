module dtls

import crypto.ecdsa
import crypto.sha256
import time
import webrtc.internal.codec
import webrtc.logging
import webrtc.srtp

// The DTLS 1.2 handshake state machine.
//
// The handshake is driven synchronously: handshake() sends a flight, waits for
// the reply, retransmits on a doubling timer, and returns when both sides have
// verified a Finished. That is a much smaller thing to get right than an
// event-driven design, and it matches how the layer is used - a caller
// establishes the connection once and then reads and writes.
//
// Only one cipher suite is implemented: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
// It is what browsers negotiate, it gives forward secrecy, and it matches the
// P-256 certificate this package generates.

// Role decides which side of the handshake to take.
pub enum Role {
	// client sends the first ClientHello. In SDP terms this is a=setup:active.
	client
	// server waits for one. In SDP terms this is a=setup:passive.
	server
}

pub fn (r Role) str() string {
	return match r {
		.client { 'client' }
		.server { 'server' }
	}
}

// State is the connection's progress.
pub enum State {
	new
	handshaking
	connected
	failed
	closed
}

pub fn (s State) str() string {
	return match s {
		.new { 'new' }
		.handshaking { 'handshaking' }
		.connected { 'connected' }
		.failed { 'failed' }
		.closed { 'closed' }
	}
}

// default_mtu is the record size the handshake fragments to.
//
// 1200 bytes is the conservative figure WebRTC implementations use: it fits
// inside the smallest path MTU likely to be encountered, including an IPv6
// tunnel, without relying on IP fragmentation, which many paths drop.
pub const default_mtu = 1200

// default_handshake_timeout bounds the whole handshake.
pub const default_handshake_timeout = 30 * time.second

// default_retransmit_interval is the initial retransmission timer, doubling on
// each attempt as RFC 6347 section 4.2.4.1 requires.
pub const default_retransmit_interval = 500 * time.millisecond

// max_handshake_messages bounds how many messages one handshake may involve.
// A peer that keeps sending new message sequences is either broken or trying to
// make us allocate.
const max_handshake_messages = 32

// Transport is the datagram channel a DTLS connection runs over.
//
// It is an interface rather than a concrete socket so that the connection can
// run over anything: an ICE agent, a plain UDP socket, or an in-memory pipe for
// testing. An ice.Agent satisfies it as written, which is the intended pairing -
// ICE finds the path, DTLS secures it.
//
// recv must return an error when the timeout expires rather than blocking
// forever; the retransmission timer depends on it.
pub interface Transport {
mut:
	send(data []u8) !int
	recv(timeout time.Duration) ![]u8
}

// Config configures a connection.
@[params]
pub struct Config {
pub:
	role Role = .client
	// certificate is the local identity. One is generated if none is given,
	// but an application that has already published a fingerprint in an offer
	// must pass the certificate that fingerprint belongs to.
	certificate ?Certificate
	// remote_fingerprints are the fingerprints signalled by the peer. The
	// handshake fails unless the peer's certificate matches one of them.
	//
	// Leaving this empty disables the check, which removes the only thing
	// authenticating the peer - anyone able to reach the transport could
	// complete the handshake. It is allowed because a caller may verify the
	// certificate itself, and refused by default because it must be a decision
	// rather than an oversight.
	remote_fingerprints []Fingerprint
	// insecure_skip_fingerprint_verification must be set explicitly to accept
	// any peer certificate.
	insecure_skip_fingerprint_verification bool
	// srtp_profiles are the SRTP protection profiles to negotiate, in order of
	// preference. Empty means do not offer DTLS-SRTP at all.
	srtp_profiles       []srtp.Profile = [srtp.Profile.aead_aes_128_gcm, .aes128_cm_hmac_sha1_80]
	handshake_timeout   time.Duration  = default_handshake_timeout
	retransmit_interval time.Duration  = default_retransmit_interval
	mtu                 int            = default_mtu
	logger              logging.Logger = logging.nop()
}

// ConnError is returned when a connection cannot be established or used.
pub struct ConnError {
pub:
	reason ConnErrorReason
	detail string
}

pub enum ConnErrorReason {
	// closed: the connection has been shut down.
	closed
	// wrong_state: the operation is not valid yet, most often reading before
	// the handshake completed.
	wrong_state
	// timed_out: the peer did not answer within the handshake timeout.
	timed_out
	// handshake_failure: the peer sent something the handshake cannot proceed
	// from.
	handshake_failure
	// fingerprint_mismatch: the peer's certificate does not match what the
	// signalling channel said it would be. This is the check that authenticates
	// the peer; a mismatch means talking to someone else.
	fingerprint_mismatch
	// bad_certificate: the peer's certificate could not be parsed or its key
	// could not be used.
	bad_certificate
	// bad_signature: a signature in the handshake did not verify.
	bad_signature
	// no_srtp_profile: DTLS-SRTP was requested and no common profile was found.
	no_srtp_profile
	// transport: the underlying datagram channel failed.
	transport
	// alert: the peer sent a fatal alert.
	alert
}

pub fn (e ConnError) msg() string {
	return 'dtls: ${e.reason}: ${e.detail}'
}

pub fn (e ConnError) code() int {
	return int(e.reason) + 40
}