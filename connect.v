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