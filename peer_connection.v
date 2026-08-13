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