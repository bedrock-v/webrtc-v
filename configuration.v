// Package webrtc assembles the protocol layers into an RTCPeerConnection.
//
// Everything below this module - ICE, DTLS, SCTP, SRTP, the codecs - can be
// used directly, and `examples/datachannel` shows what that looks like. This
// module exists because doing it by hand means knowing which end becomes the
// DTLS client, which stream identifiers each side may use, what belongs in an
// offer and what an answer may change. Those rules are JSEP, and they are the
// same for everyone.
module webrtc

import time
import webrtc.datachannel
import webrtc.dtls
import webrtc.ice
import webrtc.logging
import webrtc.sctp
import webrtc.srtp

// IceServer is a STUN or TURN server to gather candidates from.
pub struct IceServer {
pub:
	// urls are "stun:host:port" or "turn:host:port" entries, or a plain
	// "host:port" which is taken as STUN.
	//
	// A "turns:" URL is accepted and treated as "turn:": TURN over TLS is not
	// implemented, and the credentials would go out in the clear, so it is
	// refused rather than silently downgraded.
	urls []string
	// username and credential are the long-term credentials a relay requires.
	username   string
	credential string
}

// is_turn reports whether a URL names a relay rather than a STUN server.
fn is_turn_url(url string) bool {
	return url.starts_with('turn:') || url.starts_with('turns:')
}

// Configuration configures a peer connection, mirroring RTCConfiguration.
@[params]
pub struct Configuration {
pub:
	ice_servers []IceServer
	// certificate is the DTLS identity. One is generated if none is given.
	// Supplying one lets an application keep a stable fingerprint across
	// connections, which is what a caller that has already published it needs.
	certificate ?dtls.Certificate
	// interfaces filters which local addresses become ICE candidates. It is a
	// privacy control as much as a connectivity one - every address gathered is
	// disclosed to the peer.
	interfaces ice.InterfaceOptions
	// ice_gather_policy limits which candidate types are gathered, mirroring
	// RTCIceTransportPolicy. `relay_only` needs TURN and is refused until it
	// exists, rather than quietly falling back to disclosing host addresses.
	ice_gather_policy ice.GatherPolicy = .all
	// srtp_profiles are the SRTP protection profiles to offer, most preferred
	// first.
	srtp_profiles []srtp.Profile = [srtp.Profile.aead_aes_128_gcm, .aes128_cm_hmac_sha1_80]
	// max_message_size is the largest data channel message this end will accept.
	max_message_size int = sctp.default_max_message_size
	// ice_timeout bounds how long connectivity checks may run.
	ice_timeout time.Duration = 30 * time.second
	// dtls_timeout bounds the DTLS handshake.
	dtls_timeout time.Duration = 30 * time.second
	// sctp_timeout bounds the SCTP association handshake.
	sctp_timeout time.Duration  = 20 * time.second
	logger       logging.Logger = logging.nop()
}

// SignalingState follows the RTCSignalingState values that apply without
// renegotiation.
pub enum SignalingState {
	stable
	have_local_offer
	have_remote_offer
	closed
}

pub fn (s SignalingState) str() string {
	return match s {
		.stable { 'stable' }
		.have_local_offer { 'have-local-offer' }
		.have_remote_offer { 'have-remote-offer' }
		.closed { 'closed' }
	}
}

// ConnectionState aggregates the transports, following
// RTCPeerConnectionState.
pub enum ConnectionState {
	new
	connecting
	connected
	disconnected
	failed
	closed
}

pub fn (s ConnectionState) str() string {
	return match s {
		.new { 'new' }
		.connecting { 'connecting' }
		.connected { 'connected' }
		.disconnected { 'disconnected' }
		.failed { 'failed' }
		.closed { 'closed' }
	}
}

// SdpType is whether a description is an offer or an answer.
pub enum SdpType {
	offer
	answer
}

pub fn (t SdpType) str() string {
	return match t {
		.offer { 'offer' }
		.answer { 'answer' }
	}
}

pub fn sdp_type_from_string(s string) ?SdpType {
	return match s.to_lower() {
		'offer' { SdpType.offer }
		'answer' { SdpType.answer }
		else { none }
	}
}

// SessionDescription is an offer or an answer, in the shape the browser API
// uses: a type and the SDP text.
pub struct SessionDescription {
pub:
	typ SdpType
	sdp string
}

// MediaKind is what a media section carries.
pub enum MediaKind {
	audio
	video
	application
}

pub fn (k MediaKind) str() string {
	return match k {
		.audio { 'audio' }
		.video { 'video' }
		.application { 'application' }
	}
}

// Codec describes one payload type in a media section.
pub struct Codec {
pub:
	payload_type u8
	// name is the encoding name, such as "opus" or "VP8".
	name       string
	clock_rate u32
	// channels is the audio channel count; zero omits it, which is what video
	// requires.
	channels int
	// fmtp is the format parameter string, without the payload type.
	fmtp string
	// rtcp_feedback are the `a=rtcp-fb` values, without the payload type.
	rtcp_feedback []string
}

// opus_48000_2 and vp8_90000 are the two codecs almost every session starts
// from. They are here so a caller does not have to remember the numbers.
pub const opus_48000_2 = Codec{
	payload_type:  111
	name:          'opus'
	clock_rate:    48000
	channels:      2
	fmtp:          'minptime=10;useinbandfec=1'
	rtcp_feedback: ['transport-cc']
}

pub const vp8_90000 = Codec{
	payload_type:  96
	name:          'VP8'
	clock_rate:    90000
	rtcp_feedback: ['goog-remb', 'transport-cc', 'ccm fir', 'nack', 'nack pli']
}

// PeerError is returned when a connection cannot be configured or driven.
pub struct PeerError {
pub:
	reason PeerErrorReason
	detail string
}

pub enum PeerErrorReason {
	// closed: the connection has been closed.
	closed
	// wrong_state: the operation is not valid in the current signalling state.
	wrong_state
	// bad_description: the offer or answer could not be parsed, or is missing
	// something required.
	bad_description
	// unsupported: the peer asked for something this implementation does not do.
	unsupported
	// timed_out: a transport did not come up in time.
	timed_out
	// transport: a transport failed.
	transport
	// no_media: the operation needs a negotiated media section and there is none.
	no_media
}