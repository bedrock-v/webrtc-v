module webrtc

import webrtc.dtls
import webrtc.ice
import webrtc.sctp
import webrtc.srtp

// A snapshot of what a connection is doing.
//
// This is deliberately a plain value taken under the connection's lock rather
// than a live view: reading a field at a time from the transports while they
// run would produce a picture that never existed. What is here is what a
// diagnostic needs - which path was chosen, what was negotiated, how far the
// bring-up got.

// Statistics describes a connection at one instant.
pub struct Statistics {
pub:
	connection_state ConnectionState
	signaling_state  SignalingState
	// dtls_role is which end this one is; it also decides the SCTP role and the
	// data channel stream parity.
	dtls_role dtls.Role
	// ice is the agent's own snapshot, including the selected pair.
	ice ice.Statistics
	// dtls_state is none until the transport exists.
	dtls_state ?dtls.State
	// srtp_profile is none unless a media section was negotiated.
	srtp_profile ?srtp.Profile
	// sctp_state is none unless a data section was negotiated.
	sctp_state ?sctp.State
	// max_message_size is the largest data channel message this end will send,
	// which is the smaller of the two ends' limits.
	max_message_size int
	// data_channels counts the channels currently open in either direction.
	data_channels int
	// media reports whether SRTP keys are installed and media may flow.
	media_ready bool
}

// statistics returns a snapshot of the connection.
pub fn (mut pc PeerConnection) statistics() Statistics {
	pc.mu.lock()
	connection_state := pc.state
	signaling_state := pc.signaling
	role := pc.role
	mut agent := pc.agent
	mut conn := pc.dtls_conn
	mut association := pc.association
	mut media := pc.media_transport
	mut open := pc.open_channels.clone()
	pc.mu.unlock()

	mut counted := 0
	for mut channel in open {
		if channel.state() == .open {
			counted++
		}
	}

	mut ice_stats := ice.Statistics{}
	if agent != unsafe { nil } {
		ice_stats = agent.statistics()
	}

	mut dtls_state := ?dtls.State(none)
	mut srtp_profile := ?srtp.Profile(none)
	if conn != unsafe { nil } {
		dtls_state = conn.state()
		if profile := conn.selected_srtp_profile() {
			srtp_profile = profile
		}
	}

	mut sctp_state := ?sctp.State(none)
	mut max_message_size := pc.config.max_message_size
	if association != unsafe { nil } {
		sctp_state = association.state()
		max_message_size = association.max_message_size()
	}

	return Statistics{
		connection_state: connection_state
		signaling_state:  signaling_state
		dtls_role:        role
		ice:              ice_stats
		dtls_state:       dtls_state
		srtp_profile:     srtp_profile
		sctp_state:       sctp_state
		max_message_size: max_message_size
		data_channels:    counted
		media_ready:      media != unsafe { nil } && media.is_keyed()
	}
}

// str renders the snapshot as one readable line, which is what a log or a
// bug report wants.
pub fn (s Statistics) str() string {
	mut parts := ['state=${s.connection_state}', 'signaling=${s.signaling_state}',
		'ice=${s.ice.state}', 'role=${s.dtls_role}']
	if state := s.dtls_state {
		parts << 'dtls=${state}'
	}
	if state := s.sctp_state {
		parts << 'sctp=${state}'
	}
	if profile := s.srtp_profile {
		parts << 'srtp=${profile}'
	}
	parts << 'channels=${s.data_channels}'
	if pair := s.ice.selected {
		parts << 'pair=${pair.local.address}->${pair.remote.address}'
	}
	return parts.join(' ')
}
