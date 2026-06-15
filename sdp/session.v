// Package sdp implements the Session Description Protocol (RFC 8866, formerly
// RFC 4566) together with the attributes WebRTC layers on top of it.
//
// SDP is the format WebRTC offers and answers are written in. This package
// treats it as data: it parses and serialises descriptions and gives typed
// access to the attributes that matter, but it does not decide what belongs in
// an offer. That is the job of the peerconnection layer, which sits above it.
module sdp

import strings

// Direction is the media direction declared by a sendrecv, sendonly, recvonly
// or inactive attribute (RFC 8866 section 6.7).
pub enum Direction {
	// unspecified means no direction attribute was present. RFC 8866 says the
	// default is sendrecv, but "absent" and "explicitly sendrecv" are different
	// facts and the distinction matters when re-offering, so it is preserved.
	unspecified
	sendrecv
	sendonly
	recvonly
	inactive
}