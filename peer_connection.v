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