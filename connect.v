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