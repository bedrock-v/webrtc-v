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