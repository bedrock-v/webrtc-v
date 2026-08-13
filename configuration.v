// Package webrtc assembles the protocol layers into an RTCPeerConnection.
//
// Everything below this module - ICE, DTLS, SCTP, SRTP, the codecs - can be
// used directly, and `examples/datachannel` shows what that looks like. This
// module exists because doing it by hand means knowing which end becomes the
// DTLS client, which stream identifiers each side may use, what belongs in an
// offer and what an answer may change. Those rules are JSEP, and they are the
// same for everyone.
module webrtc