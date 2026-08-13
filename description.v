module webrtc

import webrtc.dtls
import webrtc.internal.randutil
import webrtc.sctp
import webrtc.sdp

// Building and reading offers and answers.
//
// Everything in a WebRTC offer that matters is per-section: the ICE
// credentials, the DTLS fingerprint and role, the codecs. Everything in this
// implementation is bundled onto one transport, so those values are identical
// in every section - which is exactly what `a=group:BUNDLE` means and why a
// browser will not accept a description without it.

// Section is one media description in the local view of a session.
struct Section {
mut:
	kind      MediaKind
	mid       string
	direction sdp.Direction
	codecs    []Codec
	// rejected marks a section the answerer declined, which is signalled by a
	// port of zero rather than by leaving it out - the section indices have to
	// line up between the offer and the answer.
	rejected bool
}

// local_transport_parameters are the values every section repeats.
struct TransportParameters {
	ice_ufrag   string
	ice_pwd     string
	fingerprint dtls.Fingerprint
	setup       sdp.Setup
}