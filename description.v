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

// build_description assembles an offer or an answer.
fn build_description(sections []Section, parameters TransportParameters, session_id u64, version u64, max_message_size int) !string {
	mut description := sdp.SessionDescription{
		version:      0
		origin:       sdp.Origin{
			username:        '-'
			session_id:      session_id
			session_version: version
			network_type:    'IN'
			address_type:    'IP4'
			unicast_address: '127.0.0.1'
		}
		session_name: '-'
	}
	description.time_descriptions << sdp.TimeDescription{}

	mut mids := []string{cap: sections.len}
	for section in sections {
		if section.rejected {
			continue
		}
		mids << section.mid
	}
	if mids.len > 0 {
		description.attributes << sdp.Attribute{
			key:   'group'
			value: 'BUNDLE ${mids.join(' ')}'
		}
	}
	description.attributes << sdp.Attribute{
		key:   'msid-semantic'
		value: ' WMS'
	}
	// RFC 8843: every bundled section shares one ICE and DTLS transport, so the
	// extmap identifiers must not clash between them. Saying so up front is what
	// lets a peer mix one-byte and two-byte header extensions.
	description.attributes << sdp.Attribute{
		key: 'extmap-allow-mixed'
	}

	for section in sections {
		description.media_descriptions << build_section(section, parameters, max_message_size)!
	}
	return description.marshal()
}