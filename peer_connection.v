module webrtc

import sync
import time
import webrtc.datachannel
import webrtc.dtls
import webrtc.ice
import webrtc.logging
import webrtc.sctp
import webrtc.sdp
import webrtc.srtp

// PeerConnection is the top-level object: it owns the transports and drives
// them from an offer and an answer.
//
// The lifecycle mirrors the browser API. One side creates channels or media
// sections and an offer; the other applies it and answers; candidates trickle
// in either direction. Once both descriptions are set, a background thread
// brings the transports up in order - ICE, then DTLS, then SCTP - and the
// connection state follows it.
//
// A PeerConnection is safe to use from several threads.
pub struct PeerConnection {
mut:
	config Configuration
	log    logging.Logger
	mu     &sync.Mutex = sync.new_mutex()

	certificate dtls.Certificate
	session_id  u64
	version     u64

	signaling  SignalingState  = .stable
	state      ConnectionState = .new
	is_offerer bool
	// role is settled from the `a=setup` exchange and decides which end is the
	// DTLS client - and therefore the SCTP client, and which data channel
	// stream identifiers each end may use.
	role dtls.Role = .client

	sections []Section
	remote   ?RemoteDescription
	// local_sdp and remote_sdp are kept so current_local_description and its
	// counterpart can return exactly what was agreed.
	local_sdp  string
	remote_sdp string

	agent       &ice.Agent           = unsafe { nil }
	dtls_conn   &dtls.Conn           = unsafe { nil }
	association &sctp.Association    = unsafe { nil }
	channels    &datachannel.Manager = unsafe { nil }

	// pending_channels are channels asked for before the transports were up.
	// They are opened once SCTP is established, which is what lets an
	// application create a channel and then negotiate.
	pending_channels []PendingChannel
	open_channels    []&DataChannel
	// incoming carries channels the peer opened.
	incoming chan &DataChannel = chan &DataChannel{cap: 32}

	media_transport &MediaTransport = unsafe { nil }

	closed  bool
	threads []thread
}

// PendingChannel is a channel requested before the transports were ready. The
// handle is the one the application is already holding, which is what has to
// become usable once SCTP is up.
struct PendingChannel {
mut:
	handle &DataChannel = unsafe { nil }
}

// PeerConnection.new creates a connection. Nothing is opened until an offer or
// an answer is applied.
pub fn PeerConnection.new(config Configuration) !&PeerConnection {
	for server in config.ice_servers {
		for url in server.urls {
			if url.starts_with('turns:') {
				// TURN over TLS would need the credentials to travel inside a
				// TLS connection this stack does not open. Downgrading to plain
				// TURN would put them on the wire in the clear, which is worse
				// than refusing.
				return PeerError{
					reason: .unsupported
					detail: 'TURN over TLS is not implemented; use "turn:" for "${url}"'
				}
			}
			if is_turn_url(url) && (server.username == '' || server.credential == '') {
				return PeerError{
					reason: .unsupported
					detail: 'the relay "${url}" needs a username and a credential'
				}
			}
		}
	}

	certificate := config.certificate or { dtls.Certificate.generate()! }
	return &PeerConnection{
		config:      config
		log:         config.logger.with_scope('webrtc')
		certificate: certificate
		session_id:  new_session_id()!
		version:     1
	}
}

// local_fingerprint is the certificate fingerprint this connection publishes.
pub fn (pc &PeerConnection) local_fingerprint() dtls.Fingerprint {
	return pc.certificate.fingerprint(.sha256)
}

// signaling_state returns the current offer/answer state.
pub fn (mut pc PeerConnection) signaling_state() SignalingState {
	pc.mu.lock()
	defer {
		pc.mu.unlock()
	}
	return pc.signaling
}

// connection_state returns the aggregate transport state.
pub fn (mut pc PeerConnection) connection_state() ConnectionState {
	pc.mu.lock()
	defer {
		pc.mu.unlock()
	}
	return pc.state
}

// current_local_description returns the SDP this end last applied.
pub fn (mut pc PeerConnection) current_local_description() ?SessionDescription {
	pc.mu.lock()
	defer {
		pc.mu.unlock()
	}
	if pc.local_sdp == '' {
		return none
	}
	return SessionDescription{
		typ: if pc.is_offerer { SdpType.offer } else { SdpType.answer }
		sdp: pc.local_sdp
	}
}

// current_remote_description returns the SDP the peer last sent.
pub fn (mut pc PeerConnection) current_remote_description() ?SessionDescription {
	pc.mu.lock()
	defer {
		pc.mu.unlock()
	}
	if pc.remote_sdp == '' {
		return none
	}
	return SessionDescription{
		typ: if pc.is_offerer { SdpType.answer } else { SdpType.offer }
		sdp: pc.remote_sdp
	}
}

// add_media declares a media section to offer.
//
// It must be called before create_offer. Renegotiation is not implemented, so a
// section added after the first offer would never reach the peer; saying so is
// better than adding it to a description nobody will see.
pub fn (mut pc PeerConnection) add_media(kind MediaKind, direction sdp.Direction, codecs []Codec) ! {
	if kind == .application {
		return PeerError{
			reason: .wrong_state
			detail: 'use create_data_channel for the data section'
		}
	}
	if codecs.len == 0 {
		return PeerError{
			reason: .wrong_state
			detail: 'a media section needs at least one codec'
		}
	}

	pc.mu.lock()
	defer {
		pc.mu.unlock()
	}
	if pc.closed {
		return PeerError{
			reason: .closed
			detail: 'the connection is closed'
		}
	}
	if pc.signaling != .stable || pc.local_sdp != '' {
		return PeerError{
			reason: .wrong_state
			detail: 'media must be added before the first offer; renegotiation is not implemented'
		}
	}
	pc.sections << Section{
		kind:      kind
		mid:       pc.sections.len.str()
		direction: direction
		codecs:    codecs.clone()
	}
	return
}

// create_data_channel asks for a data channel.
//
// Before the transports are up this records the request and adds the data
// section to the next offer; the channel itself opens once SCTP is established.
// After that it opens immediately.
pub fn (mut pc PeerConnection) create_data_channel(label string, options DataChannelOptions) !&DataChannel {
	pc.mu.lock()
	if pc.closed {
		pc.mu.unlock()
		return PeerError{
			reason: .closed
			detail: 'the connection is closed'
		}
	}
	mut manager := pc.channels
	pc.ensure_application_section()
	pc.mu.unlock()

	if manager != unsafe { nil } {
		return pc.open_channel(label, options)
	}

	// The handle is returned unopened. Its state is `connecting` until the
	// transports come up, which is what the browser API does for a channel
	// created before negotiation.
	mut handle := &DataChannel{
		connection: pc
		label:      label
		options:    options
	}
	pc.mu.lock()
	pc.pending_channels << PendingChannel{
		handle: handle
	}
	pc.open_channels << handle
	pc.mu.unlock()
	return handle
}

// ensure_application_section adds the data section if there is not one already.
// The caller must hold the mutex.
fn (mut pc PeerConnection) ensure_application_section() {
	for section in pc.sections {
		if section.kind == .application {
			return
		}
	}
	pc.sections << Section{
		kind: .application
		mid:  pc.sections.len.str()
	}
}

// accept_data_channel returns the next channel the peer opened.
pub fn (mut pc PeerConnection) accept_data_channel(timeout time.Duration) !&DataChannel {
	if pc.is_closed() {
		return PeerError{
			reason: .closed
			detail: 'the connection is closed'
		}
	}
	select {
		channel := <-pc.incoming {
			if channel == unsafe { nil } {
				// V 0.5.2 completes a receive on a closed channel with the zero
				// value, so nil means the connection was closed while waiting.
				return PeerError{
					reason: .closed
					detail: 'the connection was closed'
				}
			}
			return channel
		}
		timeout {
			return PeerError{
				reason: .timed_out
				detail: 'no data channel opened within ${timeout.milliseconds()}ms'
			}
		}
	}
	return PeerError{
		reason: .closed
		detail: 'the connection is closed'
	}
}

// create_offer builds an offer describing what this end wants.
//
// The offer is not applied by creating it; set_local_description does that, and
// the split is what lets an application inspect or adjust the SDP first.
pub fn (mut pc PeerConnection) create_offer() !SessionDescription {
	pc.mu.lock()
	defer {
		pc.mu.unlock()
	}
	if pc.closed {
		return PeerError{
			reason: .closed
			detail: 'the connection is closed'
		}
	}
	if pc.signaling != .stable {
		return PeerError{
			reason: .wrong_state
			detail: 'an offer can only be created in the stable state, not ${pc.signaling}'
		}
	}
	if pc.sections.len == 0 {
		return PeerError{
			reason: .wrong_state
			detail: 'there is nothing to offer; add media or create a data channel first'
		}
	}

	mut agent := pc.ensure_agent()!
	ufrag, pwd := agent.local_credentials()
	text := build_description(pc.sections, TransportParameters{
		ice_ufrag:   ufrag
		ice_pwd:     pwd
		fingerprint: pc.certificate.fingerprint(.sha256)
		// An offer says actpass: the answerer picks, which avoids both ends
		// trying to be the DTLS client.
		setup: .actpass
	}, pc.session_id, pc.version, pc.config.max_message_size)!

	return SessionDescription{
		typ: .offer
		sdp: text
	}
}

// create_answer builds an answer to the offer that was applied.
pub fn (mut pc PeerConnection) create_answer() !SessionDescription {
	pc.mu.lock()
	defer {
		pc.mu.unlock()
	}
	if pc.closed {
		return PeerError{
			reason: .closed
			detail: 'the connection is closed'
		}
	}
	if pc.signaling != .have_remote_offer {
		return PeerError{
			reason: .wrong_state
			detail: 'an answer needs a remote offer; the state is ${pc.signaling}'
		}
	}

	mut agent := pc.ensure_agent()!
	ufrag, pwd := agent.local_credentials()
	setup := if pc.role == .client { sdp.Setup.active } else { sdp.Setup.passive }

	text := build_description(pc.sections, TransportParameters{
		ice_ufrag:   ufrag
		ice_pwd:     pwd
		fingerprint: pc.certificate.fingerprint(.sha256)
		setup:       setup
	}, pc.session_id, pc.version, pc.config.max_message_size)!

	return SessionDescription{
		typ: .answer
		sdp: text
	}
}

// set_local_description applies a description this end created.
pub fn (mut pc PeerConnection) set_local_description(description SessionDescription) ! {
	pc.mu.lock()
	if pc.closed {
		pc.mu.unlock()
		return PeerError{
			reason: .closed
			detail: 'the connection is closed'
		}
	}
	match description.typ {
		.offer {
			if pc.signaling != .stable {
				pc.mu.unlock()
				return PeerError{
					reason: .wrong_state
					detail: 'a local offer needs the stable state, not ${pc.signaling}'
				}
			}
			pc.is_offerer = true
			pc.signaling = .have_local_offer
		}
		.answer {
			if pc.signaling != .have_remote_offer {
				pc.mu.unlock()
				return PeerError{
					reason: .wrong_state
					detail: 'a local answer needs a remote offer, not ${pc.signaling}'
				}
			}
			pc.signaling = .stable
		}
	}
	pc.local_sdp = description.sdp
	pc.mu.unlock()

	// Gathering starts here rather than at construction: the credentials in the
	// description have to be the ones the sockets will use, and the application
	// has now committed to them.
	pc.start_gathering()!
	pc.maybe_start()
	return
}

// set_remote_description applies the peer's offer or answer.
pub fn (mut pc PeerConnection) set_remote_description(description SessionDescription) ! {
	remote := parse_remote_description(description.sdp)!

	pc.mu.lock()
	if pc.closed {
		pc.mu.unlock()
		return PeerError{
			reason: .closed
			detail: 'the connection is closed'
		}
	}

	match description.typ {
		.offer {
			if pc.signaling != .stable {
				pc.mu.unlock()
				return PeerError{
					reason: .wrong_state
					detail: 'a remote offer needs the stable state, not ${pc.signaling}'
				}
			}
			pc.is_offerer = false
			pc.signaling = .have_remote_offer
			pc.answer_sections(remote)!
			// RFC 5763: the answerer chooses, and choosing active means it
			// starts the handshake, which saves a round trip.
			offered := remote.setup or { sdp.Setup.actpass }
			pc.role = if offered.answer() == .active { dtls.Role.client } else { dtls.Role.server }
		}
		.answer {
			if pc.signaling != .have_local_offer {
				pc.mu.unlock()
				return PeerError{
					reason: .wrong_state
					detail: 'a remote answer needs a local offer, not ${pc.signaling}'
				}
			}
			pc.signaling = .stable
			pc.apply_answer(remote)!
			answered := remote.setup or {
				pc.mu.unlock()
				return PeerError{
					reason: .bad_description
					detail: 'the answer carries no setup role'
				}
			}

			if answered == .actpass {
				// An answer may not leave the roles undetermined; both ends
				// would then wait for the other to start the handshake.
				pc.mu.unlock()
				return PeerError{
					reason: .bad_description
					detail: 'the answer says actpass, which leaves the DTLS roles undetermined'
				}
			}
			// The answerer named its own role, so ours is the opposite.
			pc.role = if answered == .active { dtls.Role.server } else { dtls.Role.client }
		}
	}

	pc.remote = remote
	pc.remote_sdp = description.sdp
	candidates := remote.candidates.clone()
	mut agent := pc.agent
	ufrag := remote.ice_ufrag
	pwd := remote.ice_pwd
	pc.mu.unlock()

	if agent == unsafe { nil } {
		pc.mu.lock()
		agent = pc.ensure_agent() or {
			pc.mu.unlock()
			return err
		}
		pc.mu.unlock()
	}
	agent.set_remote_credentials(ufrag, pwd) or {
		return PeerError{
			reason: .bad_description
			detail: 'the peer ICE credentials were refused: ${err.msg()}'
		}
	}
	// Candidates carried in the description itself, for a peer that does not
	// trickle.
	for line in candidates {
		agent.add_remote_candidate_string(line) or {
			pc.log.debug('ignoring a candidate we cannot use: ${err.msg()}')
		}
	}

	pc.maybe_start()
	return
}

// answer_sections mirrors the offered sections into our own list, keeping only
// what we can carry. The caller must hold the mutex.
fn (mut pc PeerConnection) answer_sections(remote RemoteDescription) ! {
	// The answer must have the same sections, in the same order, as the offer.
	// A section we cannot use is rejected with a zero port rather than left
	// out, so the two lists stay index-aligned.
	mut wanted := pc.sections.clone()
	mut answered := []Section{cap: remote.sections.len}

	for offered in remote.sections {
		if offered.rejected {
			answered << Section{
				kind:     offered.kind
				mid:      offered.mid
				rejected: true
			}
			continue
		}
		if offered.kind == .application {
			answered << Section{
				kind: .application
				mid:  offered.mid
			}
			continue
		}

		mut local_codecs := []Codec{}
		for index, candidate in wanted {
			if candidate.kind != offered.kind {
				continue
			}
			local_codecs = intersect_codecs(offered.codecs, candidate.codecs)
			wanted.delete(index)
			break
		}
		if local_codecs.len == 0 {
			// Nothing in common, or no local section of this kind. Rejecting is
			// the correct answer and keeps the section indices aligned.
			answered << Section{
				kind:     offered.kind
				mid:      offered.mid
				rejected: true
			}
			continue
		}
		answered << Section{
			kind:      offered.kind
			mid:       offered.mid
			direction: offered.direction.reverse()
			codecs:    local_codecs
		}
	}

	pc.sections = answered
}

// apply_answer narrows our offered sections to what the peer accepted. The
// caller must hold the mutex.
fn (mut pc PeerConnection) apply_answer(remote RemoteDescription) ! {
	if remote.sections.len != pc.sections.len {
		return PeerError{
			reason: .bad_description
			detail: 'the answer has ${remote.sections.len} sections, the offer had ${pc.sections.len}'
		}
	}
	for index, answered in remote.sections {
		if answered.rejected {
			pc.sections[index].rejected = true
			continue
		}
		if pc.sections[index].kind == .application {
			continue
		}
		pc.sections[index].codecs = intersect_codecs(answered.codecs, pc.sections[index].codecs)
		// The answerer's direction is what it will do; ours is the mirror.
		pc.sections[index].direction = answered.direction.reverse()
	}
}

// add_ice_candidate applies a candidate the peer trickled.
pub fn (mut pc PeerConnection) add_ice_candidate(line string) ! {
	pc.mu.lock()
	mut agent := pc.agent
	closed := pc.closed
	pc.mu.unlock()

	if closed {
		return PeerError{
			reason: .closed
			detail: 'the connection is closed'
		}
	}
	if agent == unsafe { nil } {
		return PeerError{
			reason: .wrong_state
			detail: 'no local description has been set, so there is nothing to add the candidate to'
		}
	}
	agent.add_remote_candidate_string(line) or {
		return PeerError{
			reason: .bad_description
			detail: err.msg()
		}
	}
}

// local_candidates returns the candidates gathered so far, as SDP attribute
// values ready to signal.
pub fn (mut pc PeerConnection) local_candidates() []string {
	pc.mu.lock()
	mut agent := pc.agent
	pc.mu.unlock()
	if agent == unsafe { nil } {
		return []string{}
	}
	mut out := []string{}
	for candidate in agent.local_candidates() {
		out << 'candidate:${candidate}'
	}
	return out
}

// ensure_agent creates the ICE agent if it does not exist. The caller must hold
// the mutex.
fn (mut pc PeerConnection) ensure_agent() !&ice.Agent {
	if pc.agent != unsafe { nil } {
		return pc.agent
	}
	mut servers := []string{}
	mut relays := []ice.TurnServer{}
	for server in pc.config.ice_servers {
		for url in server.urls {
			if is_turn_url(url) {
				relays << ice.TurnServer{
					url:      url
					username: server.username
					password: server.credential
				}
				continue
			}
			servers << url.replace('stun:', '')
		}
	}
	// The offerer takes the controlling role. It is only a tiebreak - a role
	// conflict is resolved on the wire - but starting from the right one saves
	// the exchange.
	agent := ice.Agent.new(
		role:          if pc.is_offerer || pc.signaling != .have_remote_offer {
			ice.Role.controlling
		} else {
			ice.Role.controlled
		}
		stun_servers:  servers
		turn_servers:  relays
		interfaces:    pc.config.interfaces
		gather_policy: pc.config.ice_gather_policy
		logger:        pc.config.logger
	) or {
		return PeerError{
			reason: .transport
			detail: 'creating the ICE agent: ${err.msg()}'
		}
	}
	pc.agent = agent
	return agent
}

fn (mut pc PeerConnection) is_closed() bool {
	pc.mu.lock()
	defer {
		pc.mu.unlock()
	}
	return pc.closed
}

fn (mut pc PeerConnection) set_state(state ConnectionState) {
	pc.mu.lock()
	if pc.state != state && pc.state != .closed {
		pc.log.info('connection state ${pc.state} -> ${state}')
		pc.state = state
	}
	pc.mu.unlock()
}

// close tears the connection down. It is safe to call more than once.
pub fn (mut pc PeerConnection) close() {
	pc.mu.lock()
	if pc.closed {
		pc.mu.unlock()
		return
	}
	pc.closed = true
	pc.state = .closed
	pc.signaling = .closed
	mut channels := pc.channels
	mut association := pc.association
	mut agent := pc.agent
	mut media := pc.media_transport
	mut open := pc.open_channels.clone()
	pc.mu.unlock()

	for mut channel in open {
		channel.mark_closed()
	}
	if channels != unsafe { nil } {
		channels.close()
	}
	if association != unsafe { nil } {
		association.close()
	}
	if media != unsafe { nil } {
		// Before the agent, so the pump stops reading a socket that is about to
		// go away rather than logging its way through the shutdown.
		media.close()
	}
	if agent != unsafe { nil } {
		agent.close()
	}
	pc.incoming.close()

	for handle in pc.threads {
		handle.wait()
	}
	pc.mu.lock()
	pc.threads.clear()
	pc.mu.unlock()
}

// selected_candidate_pair returns the ICE pair carrying traffic.
pub fn (mut pc PeerConnection) selected_candidate_pair() ?ice.CandidatePair {
	pc.mu.lock()
	mut agent := pc.agent
	pc.mu.unlock()
	if agent == unsafe { nil } {
		return none
	}
	return agent.selected_pair()
}

// selected_srtp_profile returns the SRTP profile the DTLS handshake agreed.
pub fn (mut pc PeerConnection) selected_srtp_profile() ?srtp.Profile {
	pc.mu.lock()
	mut conn := pc.dtls_conn
	pc.mu.unlock()
	if conn == unsafe { nil } {
		return none
	}
	return conn.selected_srtp_profile()
}

// remote_certificate returns the peer's certificate, once the handshake has
// reached it.
pub fn (mut pc PeerConnection) remote_certificate() ?dtls.ParsedCertificate {
	pc.mu.lock()
	mut conn := pc.dtls_conn
	pc.mu.unlock()
	if conn == unsafe { nil } {
		return none
	}
	return conn.remote_certificate()
}
