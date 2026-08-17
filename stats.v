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