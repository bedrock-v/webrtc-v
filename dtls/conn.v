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

// pendingMessage reassembles a fragmented handshake message.
struct PendingMessage {
mut:
	typ    HandshakeType
	length u32
	body   []u8
	// received tracks which byte ranges have arrived, as sorted,
	// non-overlapping half-open spans. A bitmap would be simpler but would
	// allocate proportionally to the declared length, which the peer chooses.
	received []ByteRange
}

// ByteRange is a half-open span of a message body.
struct ByteRange {
	start u32
	end   u32
}

// add records a fragment and reports whether the message is now complete.
fn (mut p PendingMessage) add(offset u32, fragment []u8) bool {
	if u64(offset) + u64(fragment.len) > u64(p.length) {
		return p.is_complete()
	}
	for i, b in fragment {
		p.body[int(offset) + i] = b
	}
	p.merge(offset, offset + u32(fragment.len))
	return p.is_complete()
}

fn (mut p PendingMessage) merge(start u32, end u32) {
	if end <= start {
		return
	}
	mut merged := []ByteRange{cap: p.received.len + 1}
	mut lo := start
	mut hi := end
	for span in p.received {
		// Spans that touch as well as overlap are absorbed, so two adjacent
		// fragments collapse into one and the completeness test stays a single
		// comparison.
		if span.end < lo || span.start > hi {
			merged << span
			continue
		}
		if span.start < lo {
			lo = span.start
		}
		if span.end > hi {
			hi = span.end
		}
	}
	merged << ByteRange{
		start: lo
		end:   hi
	}
	merged.sort(a.start < b.start)
	p.received = merged
}

fn (p &PendingMessage) is_complete() bool {
	// A zero-length message has no bytes to record, so the span list stays
	// empty and the range test below would never be satisfied. ServerHelloDone
	// is exactly this shape and is mandatory, so getting it wrong stops every
	// handshake at the server's first flight.
	if p.length == 0 {
		return true
	}
	return p.received.len == 1 && p.received[0].start == 0 && p.received[0].end == p.length
}

// Conn is a DTLS connection.
//
// It is not safe for concurrent use by several threads. One connection belongs
// to one transport, and the record layer's sequence numbering assumes a single
// writer.
pub struct Conn {
mut:
	transport Transport
	config    Config
	log       logging.Logger

	is_client bool
	state     State

	local_certificate  Certificate
	remote_certificate ?ParsedCertificate

	local_random  Random
	remote_random Random
	cookie        []u8

	ecdh_private ecdsa.PrivateKey
	ecdh_public  ecdsa.PublicKey
	peer_ecdh    ?ecdsa.PublicKey

	master_secret []u8
	// transcript is every handshake message exchanged, in order, in the
	// unfragmented form. The Finished messages and the CertificateVerify are
	// computed over its hash, which is what makes the earlier flights
	// tamper-evident.
	transcript []u8

	send_epoch    u16
	send_sequence u64
	send_cipher   ?RecordCipher

	recv_epoch  u16
	recv_cipher ?RecordCipher
	replay      AntiReplay

	next_message_seq     u16
	expected_message_seq u16
	pending              map[u16]PendingMessage
	// saw_retransmission is set when a fragment arrives for a message sequence
	// already processed. RFC 6347 section 4.2.4 says that means the peer did
	// not get our last flight, so it should be sent again immediately rather
	// than waited out on the timer.
	saw_retransmission bool

	negotiated_srtp_profile ?srtp.Profile
	use_extended_master     bool

	// A CertificateVerify signs the transcript that precedes it, and a Finished
	// verifies over the transcript that precedes it. Since collect_handshake
	// appends a message as soon as it is complete, the state before each has to
	// be captured at that moment; recomputing it afterwards is not possible.
	transcript_at_certificate_verify []u8
	transcript_at_peer_finished      []u8

	// buffered holds application data that arrived before the caller asked for
	// it, which happens when the peer's Finished and its first data share a
	// datagram.
	buffered [][]u8
}

// Conn.new creates a connection over the given transport. No packet is sent
// until handshake is called.
pub fn Conn.new(transport Transport, config Config) !&Conn {
	if config.mtu < record_header_size + handshake_header_size + 64 {
		return ConnError{
			reason: .wrong_state
			detail: 'an MTU of ${config.mtu} bytes is too small to carry a handshake fragment'
		}
	}
	if config.remote_fingerprints.len == 0 && !config.insecure_skip_fingerprint_verification {
		return ConnError{
			reason: .wrong_state
			detail: 'no remote fingerprints were given; set insecure_skip_fingerprint_verification to accept any peer certificate'
		}
	}

	certificate := config.certificate or { Certificate.generate()! }
	public_key, private_key := ecdsa.generate_key(nid: .prime256v1) or {
		return ConnError{
			reason: .handshake_failure
			detail: 'generating an ephemeral key: ${err.msg()}'
		}
	}

	return &Conn{
		transport:         transport
		config:            config
		log:               config.logger.with_scope('dtls')
		is_client:         config.role == .client
		state:             .new
		local_certificate: certificate
		local_random:      Random.generate()!
		ecdh_private:      private_key
		ecdh_public:       public_key
		replay:            AntiReplay.new(default_replay_window)
	}
}

// state returns the connection's current state.
@[inline]
pub fn (c &Conn) state() State {
	return c.state
}

// role returns which side of the handshake this connection took.
@[inline]
pub fn (c &Conn) role() Role {
	return if c.is_client { Role.client } else { Role.server }
}

// local_certificate returns the certificate this end presents, whose
// fingerprint belongs in the local SDP.
@[inline]
pub fn (c &Conn) local_certificate() Certificate {
	return c.local_certificate
}

// remote_certificate returns the peer's certificate, once the handshake has
// reached the point of receiving it.
pub fn (c &Conn) remote_certificate() ?ParsedCertificate {
	return c.remote_certificate
}

// selected_srtp_profile returns the negotiated SRTP protection profile.
pub fn (c &Conn) selected_srtp_profile() ?srtp.Profile {
	return c.negotiated_srtp_profile
}

// srtp_keying_material exports the keys for the negotiated SRTP profile
// (RFC 5764 section 4.2).
//
// Split it with srtp.split_keying_material. Which half is the local one depends
// on the DTLS role, not on the ICE role: the client's key protects what the
// client sends.
pub fn (c &Conn) srtp_keying_material() ![]u8 {
	if c.state != .connected {
		return ConnError{
			reason: .wrong_state
			detail: 'keying material is only available after the handshake completes'
		}
	}
	profile := c.negotiated_srtp_profile or {
		return ConnError{
			reason: .no_srtp_profile
			detail: 'no SRTP profile was negotiated'
		}
	}

	client_random, server_random := c.client_and_server_randoms()
	return srtp_keying_material(c.master_secret, client_random, server_random,
		profile.keying_material_len())
}

// srtp_contexts builds the two SRTP contexts for this connection, keyed and
// pointed in the right directions.
pub fn (c &Conn) srtp_contexts() !(&srtp.Context, &srtp.Context) {
	profile := c.negotiated_srtp_profile or {
		return ConnError{
			reason: .no_srtp_profile
			detail: 'no SRTP profile was negotiated'
		}
	}

	material := c.srtp_keying_material()!
	client_keys, server_keys := srtp.split_keying_material(material, profile)!

	// The client half protects what the DTLS client sends.
	local, remote := if c.is_client {
		client_keys, server_keys
	} else {
		server_keys, client_keys
	}
	outbound := srtp.Context.from_keying_material(local, profile)!
	inbound := srtp.Context.from_keying_material(remote, profile)!
	return outbound, inbound
}

// close marks the connection closed. It does not send a close_notify alert,
// because in WebRTC the transport below is torn down at the same moment and an
// alert would be sent into a socket that is already going away.
pub fn (mut c Conn) close() {
	if c.state == .closed {
		return
	}
	c.state = .closed
}

// client_and_server_randoms returns the two handshake randoms in the order
// every derivation in TLS names them, which is by role and not by which end is
// asking.
//
// Getting this backwards on one side produces two peers that complete a
// handshake and then derive different keys, with nothing to point at the cause.
// It is computed in one place so the several derivations that need it cannot
// disagree.
fn (c &Conn) client_and_server_randoms() ([]u8, []u8) {
	if c.is_client {
		return c.local_random.bytes, c.remote_random.bytes
	}
	return c.remote_random.bytes, c.local_random.bytes
}

// transcript_hash is the SHA-256 of every handshake message so far.
fn (c &Conn) transcript_hash() []u8 {
	return transcript_hash_of(c.transcript)
}