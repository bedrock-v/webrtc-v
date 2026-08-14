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