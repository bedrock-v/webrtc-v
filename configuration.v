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