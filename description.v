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

fn build_section(section Section, parameters TransportParameters, max_message_size int) !sdp.MediaDescription {
	mut media := sdp.MediaDescription{
		media: section.kind.str()
		// Port 9 is the discard port. The real address comes from ICE, and a
		// section is offered with a placeholder; zero is reserved for rejecting
		// it, which is why it cannot double as "not applicable".
		port: if section.rejected { 0 } else { 9 }
	}
	media.connection = sdp.ConnectionData{
		network_type: 'IN'
		address_type: 'IP4'
		address:      '0.0.0.0'
	}

	if section.kind == .application {
		media.protos = ['UDP', 'DTLS', 'SCTP']
		media.formats = ['webrtc-datachannel']
	} else {
		media.protos = ['UDP', 'TLS', 'RTP', 'SAVPF']
		for codec in section.codecs {
			media.formats << codec.payload_type.str()
		}
	}

	if section.rejected {
		// A rejected section keeps its mid so the two sides' section lists stay
		// aligned, and carries nothing else.
		media.attributes << sdp.Attribute{
			key:   'mid'
			value: section.mid
		}
		return media
	}

	media.attributes << sdp.Attribute{
		key:   'ice-ufrag'
		value: parameters.ice_ufrag
	}
	media.attributes << sdp.Attribute{
		key:   'ice-pwd'
		value: parameters.ice_pwd
	}
	media.attributes << sdp.Attribute{
		key:   'ice-options'
		value: 'trickle'
	}
	media.attributes << sdp.Attribute{
		key:   'fingerprint'
		value: parameters.fingerprint.str()
	}
	media.attributes << sdp.Attribute{
		key:   'setup'
		value: parameters.setup.str()
	}
	media.attributes << sdp.Attribute{
		key:   'mid'
		value: section.mid
	}

	if section.kind == .application {
		media.attributes << sdp.Attribute{
			key:   'sctp-port'
			value: sctp.webrtc_port.str()
		}
		media.attributes << sdp.Attribute{
			key:   'max-message-size'
			value: max_message_size.str()
		}
		return media
	}

	if section.direction != .unspecified {
		media.attributes << sdp.Attribute{
			key: section.direction.str()
		}
	}
	// RTP and RTCP share one port. Every WebRTC endpoint does this, and the
	// alternative would need a second ICE component.
	media.attributes << sdp.Attribute{
		key: 'rtcp-mux'
	}

	for codec in section.codecs {
		mut rtpmap := '${codec.payload_type} ${codec.name}/${codec.clock_rate}'
		if codec.channels > 0 {
			rtpmap += '/${codec.channels}'
		}
		media.attributes << sdp.Attribute{
			key:   'rtpmap'
			value: rtpmap
		}
		for feedback in codec.rtcp_feedback {
			media.attributes << sdp.Attribute{
				key:   'rtcp-fb'
				value: '${codec.payload_type} ${feedback}'
			}
		}
		if codec.fmtp != '' {
			media.attributes << sdp.Attribute{
				key:   'fmtp'
				value: '${codec.payload_type} ${codec.fmtp}'
			}
		}
	}
	return media
}