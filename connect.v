module webrtc

import time
import webrtc.datachannel
import webrtc.dtls
import webrtc.sctp

// Bringing the transports up, in order, on a background thread.
//
// ICE has to connect before DTLS can handshake, DTLS before SCTP can associate,
// and SCTP before a data channel can open. Doing that on a thread rather than
// inside set_remote_description is what keeps the signalling calls from
// blocking for the length of a connection attempt.

// start_gathering opens the sockets and gathers candidates.
fn (mut pc PeerConnection) start_gathering() ! {
	pc.mu.lock()
	mut agent := pc.agent
	pc.mu.unlock()
	if agent == unsafe { nil } {
		return PeerError{
			reason: .wrong_state
			detail: 'no ICE agent; set a local description first'
		}
	}
	agent.gather() or {
		pc.set_state(.failed)
		return PeerError{
			reason: .transport
			detail: 'gathering candidates: ${err.msg()}'
		}
	}
}

// maybe_start launches the bring-up once both descriptions are in place.
fn (mut pc PeerConnection) maybe_start() {
	pc.mu.lock()
	ready := !pc.closed && pc.signaling == .stable && pc.local_sdp != '' && pc.remote_sdp != ''
		&& pc.threads.len == 0 && pc.agent != unsafe { nil }
	if !ready {
		pc.mu.unlock()
		return
	}
	pc.state = .connecting
	pc.mu.unlock()

	pc.threads << spawn pc.bring_up()
}

// bring_up runs the transports in sequence.
fn (mut pc PeerConnection) bring_up() {
	pc.connect_ice() or {
		pc.log.warn('ICE failed: ${err.msg()}')
		pc.set_state(.failed)
		return
	}
	pc.connect_dtls() or {
		pc.log.warn('DTLS failed: ${err.msg()}')
		pc.set_state(.failed)
		return
	}
	if pc.has_application_section() {
		pc.connect_sctp() or {
			pc.log.warn('SCTP failed: ${err.msg()}')
			pc.set_state(.failed)
			return
		}
	}
	// The channels asked for before negotiation are opened before the state is
	// announced, so that a caller waiting on wait_connected can send as soon as
	// it returns rather than racing the DCEP exchange.
	pc.open_pending_channels()
	pc.set_state(.connected)
	pc.watch()
}

fn (mut pc PeerConnection) connect_ice() ! {
	pc.mu.lock()
	mut agent := pc.agent
	timeout := pc.config.ice_timeout
	pc.mu.unlock()

	agent.connect(timeout) or { return PeerError{
		reason: .timed_out
		detail: err.msg()
	} }
	pc.log.debug('ICE connected')
}

fn (mut pc PeerConnection) connect_dtls() ! {
	pc.mu.lock()
	mut agent := pc.agent
	role := pc.role
	certificate := pc.certificate
	remote := pc.remote or {
		pc.mu.unlock()
		return PeerError{
			reason: .wrong_state
			detail: 'no remote description'
		}
	}

	config := pc.config
	pc.mu.unlock()

	// With a media section the socket carries DTLS and SRTP together, so the
	// handshake reads through the demultiplexer rather than from the agent -
	// otherwise the DTLS layer would consume RTP packets and drop them.
	transport := if pc.has_media_section() {
		media := MediaTransport.new(mut agent, config.logger)
		pc.mu.lock()
		pc.media_transport = media
		pc.mu.unlock()
		dtls.Transport(media)
	} else {
		dtls.Transport(agent)
	}

	mut conn := dtls.Conn.new(transport,
		role:                role
		certificate:         certificate
		remote_fingerprints: remote.fingerprints
		srtp_profiles:       config.srtp_profiles
		handshake_timeout:   config.dtls_timeout
		logger:              config.logger
	) or {
		return PeerError{
			reason: .transport
			detail: 'creating the DTLS transport: ${err.msg()}'
		}
	}

	pc.mu.lock()
	pc.dtls_conn = conn
	pc.mu.unlock()

	conn.handshake() or {
		return PeerError{
			reason: .transport
			detail: 'DTLS handshake: ${err.msg()}'
		}
	}
	pc.log.debug('DTLS connected as ${role}')

	// Media, if any section survived negotiation, is protected with the keys
	// this handshake exported.
	if pc.has_media_section() {
		pc.attach_media(mut conn) or { pc.log.warn('media transport unavailable: ${err.msg()}') }
	}
}

fn (mut pc PeerConnection) connect_sctp() ! {
	pc.mu.lock()
	mut conn := pc.dtls_conn
	role := pc.role
	config := pc.config
	// The peer's advertised maximum bounds what we may send it; ours bounds what
	// we will accept and it is what we advertised in turn. They are separate
	// promises, so there is nothing to reconcile between them: a peer that
	// accepts less than we do has not changed what we accept.
	mut peer_max := config.max_message_size
	if remote := pc.remote {
		if advertised := remote.max_message_size {
			peer_max = advertised
		}
	}
	pc.mu.unlock()

	// RFC 8841: the DTLS client is the SCTP client.
	mut association := sctp.Association.new(conn,
		role:                  if role == .client { sctp.Role.client } else { sctp.Role.server }
		max_message_size:      config.max_message_size
		peer_max_message_size: peer_max
		logger:                config.logger
	) or {
		return PeerError{
			reason: .transport
			detail: 'creating the SCTP association: ${err.msg()}'
		}
	}

	pc.mu.lock()
	pc.association = association
	pc.mu.unlock()

	association.connect(config.sctp_timeout) or {
		return PeerError{
			reason: .transport
			detail: 'SCTP association: ${err.msg()}'
		}
	}

	// RFC 8832 gives the DTLS client the even stream identifiers.
	manager := datachannel.Manager.new(association,
		is_dtls_client: role == .client
		logger:         config.logger
	)
	pc.mu.lock()
	pc.channels = manager
	pc.mu.unlock()

	pc.threads << spawn pc.accept_channels()
	pc.log.debug('SCTP associated, data channels ready')
}

// open_pending_channels opens the channels asked for before the transports were
// up.
fn (mut pc PeerConnection) open_pending_channels() {
	pc.mu.lock()
	pending := pc.pending_channels.clone()
	pc.pending_channels.clear()
	pc.mu.unlock()

	for request in pending {
		mut handle := request.handle
		if handle == unsafe { nil } {
			continue
		}
		pc.bind_channel(mut handle) or {
			pc.log.warn('could not open the channel "${handle.label}": ${err.msg()}')
			continue
		}
	}
}

// accept_channels forwards channels the peer opens.
fn (mut pc PeerConnection) accept_channels() {
	for {
		if pc.is_closed() {
			return
		}
		pc.mu.lock()
		mut manager := pc.channels
		pc.mu.unlock()
		if manager == unsafe { nil } {
			return
		}

		channel := manager.accept(200 * time.millisecond) or {
			if err is datachannel.ChannelError && err.reason == .timed_out {
				continue
			}
			return
		}
		mut wrapper := &DataChannel{
			connection: pc
			label:      channel.label
			channel:    channel
		}
		pc.mu.lock()
		pc.open_channels << wrapper
		pc.mu.unlock()

		select {
			pc.incoming <- wrapper {}
			else {
				pc.log.warn('the incoming channel queue is full; "${channel.label}" was dropped')
				wrapper.close()
			}
		}
	}
}

// watch follows the transports after the connection is up, so that a path that
// dies is reported rather than silently stopping.
fn (mut pc PeerConnection) watch() {
	for {
		if pc.is_closed() {
			return
		}
		pc.mu.lock()
		mut agent := pc.agent
		mut association := pc.association
		needs_sctp := pc.association != unsafe { nil }
		pc.mu.unlock()

		if agent == unsafe { nil } {
			return
		}
		ice_state := agent.state()
		mut next := ConnectionState.connected
		match ice_state {
			.failed, .closed { next = .failed }
			.disconnected { next = .disconnected }
			else {}
		}
		if next == .connected && needs_sctp {
			match association.state() {
				.aborted { next = .failed }
				.closed { next = .disconnected }
				else {}
			}
		}
		pc.set_state(next)
		if next == .failed {
			return
		}
		time.sleep(200 * time.millisecond)
	}
}

// wait_connected blocks until the transports are up.
//
// It exists because the bring-up is asynchronous and most callers, having
// exchanged an offer and an answer, simply want to wait for the result.
pub fn (mut pc PeerConnection) wait_connected(timeout time.Duration) ! {
	deadline := time.now().add(timeout)
	for time.now() < deadline {
		match pc.connection_state() {
			.connected {
				return
			}
			.failed {
				return PeerError{
					reason: .transport
					detail: 'the connection failed'
				}
			}
			.closed {
				return PeerError{
					reason: .closed
					detail: 'the connection was closed'
				}
			}
			else {}
		}
		time.sleep(5 * time.millisecond)
	}
	return PeerError{
		reason: .timed_out
		detail: 'not connected within ${timeout.milliseconds()}ms'
	}
}

fn (mut pc PeerConnection) has_application_section() bool {
	pc.mu.lock()
	defer {
		pc.mu.unlock()
	}
	for section in pc.sections {
		if section.kind == .application && !section.rejected {
			return true
		}
	}
	return false
}

fn (mut pc PeerConnection) has_media_section() bool {
	pc.mu.lock()
	defer {
		pc.mu.unlock()
	}
	for section in pc.sections {
		if section.kind != .application && !section.rejected && section.codecs.len > 0 {
			return true
		}
	}
	return false
}
