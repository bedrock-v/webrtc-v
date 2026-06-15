// Package sdp implements the Session Description Protocol (RFC 8866, formerly
// RFC 4566) together with the attributes WebRTC layers on top of it.
//
// SDP is the format WebRTC offers and answers are written in. This package
// treats it as data: it parses and serialises descriptions and gives typed
// access to the attributes that matter, but it does not decide what belongs in
// an offer. That is the job of the peerconnection layer, which sits above it.
module sdp