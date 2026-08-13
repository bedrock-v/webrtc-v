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

// RemoteDescription is what a peer's offer or answer told us.
struct RemoteDescription {
mut:
	ice_ufrag    string
	ice_pwd      string
	fingerprints []dtls.Fingerprint
	setup        ?sdp.Setup
	sections     []RemoteSection
	// candidates are any `a=candidate` lines carried in the description itself,
	// which is how a non-trickling peer sends them.
	candidates []string
	// max_message_size is what the peer will accept on a data channel.
	max_message_size ?int
	parsed           sdp.SessionDescription
}

struct RemoteSection {
mut:
	kind      MediaKind
	mid       string
	direction sdp.Direction
	codecs    []Codec
	rejected  bool
}

// parse_remote_description reads a peer's SDP into the values the transports
// need.
//
// The transport parameters are taken from the first section that carries them:
// with BUNDLE they are identical everywhere, and a description that disagrees
// between sections is describing something this implementation does not do.
fn parse_remote_description(text string) !RemoteDescription {
	parsed := sdp.parse(text) or {
		return PeerError{
			reason: .bad_description
			detail: err.msg()
		}
	}
	if parsed.media_descriptions.len == 0 {
		return PeerError{
			reason: .bad_description
			detail: 'the description has no media sections'
		}
	}

	mut remote := RemoteDescription{
		parsed: parsed
	}

	for index, media in parsed.media_descriptions {
		mid := media.mid() or { index.str() }
		kind := match media.media {
			'audio' {
				MediaKind.audio
			}
			'video' {
				MediaKind.video
			}
			'application' {
				MediaKind.application
			}
			else {
				return PeerError{
					reason: .unsupported
					detail: 'media type "${media.media}" is not supported'
				}
			}
		}

		mut section := RemoteSection{
			kind:      kind
			mid:       mid
			direction: media.direction()
			rejected:  media.is_rejected()
		}
		for codec in media.rtpmaps() {
			section.codecs << Codec{
				payload_type:  codec.payload_type
				name:          codec.encoding_name
				clock_rate:    codec.clock_rate
				channels:      if codec.encoding_params != '' {
					codec.encoding_params.int()
				} else {
					0
				}
				fmtp:          media.fmtp(codec.payload_type) or { '' }
				rtcp_feedback: feedback_for(media, codec.payload_type)
			}
		}
		remote.sections << section

		if media.is_rejected() {
			continue
		}
		for line in media.candidates() {
			remote.candidates << line
		}
		if size := media.max_message_size() {
			remote.max_message_size = int(size)
		}
		if remote.ice_ufrag == '' {
			if ufrag := parsed.ice_ufrag(media) {
				remote.ice_ufrag = ufrag
			}
			if pwd := parsed.ice_pwd(media) {
				remote.ice_pwd = pwd
			}
			for fingerprint in parsed.fingerprints(media) {
				// A hash this end cannot compute is skipped rather than
				// refused: a peer may list several, and one it shares with us
				// is enough to authenticate the certificate.
				remote.fingerprints << dtls.Fingerprint.parse(fingerprint.str()) or { continue }
			}
			remote.setup = parsed.setup(media)
		}
	}

	if remote.ice_ufrag == '' || remote.ice_pwd == '' {
		return PeerError{
			reason: .bad_description
			detail: 'the description carries no ICE credentials'
		}
	}
	if remote.fingerprints.len == 0 {
		// Without a fingerprint there is nothing to authenticate the peer
		// against, and the DTLS handshake would be with whoever answered.
		return PeerError{
			reason: .bad_description
			detail: 'the description carries no DTLS fingerprint'
		}
	}
	return remote
}

fn feedback_for(media sdp.MediaDescription, payload_type u8) []string {
	mut out := []string{}
	for feedback in media.rtcp_feedback() {
		if !feedback.wildcard && feedback.payload_type != payload_type {
			continue
		}
		if feedback.parameter == '' {
			out << feedback.typ
		} else {
			out << '${feedback.typ} ${feedback.parameter}'
		}
	}
	return out
}

// intersect_codecs keeps the offered codecs this end also has, in the offerer's
// order.
//
// The answerer must reuse the offerer's payload type numbers: they are the
// offerer's to assign, and renumbering them would leave the two ends decoding
// different things under the same number.
fn intersect_codecs(offered []Codec, supported []Codec) []Codec {
	mut out := []Codec{}
	for candidate in offered {
		for local in supported {
			if candidate.name.to_lower() != local.name.to_lower() {
				continue
			}
			if candidate.clock_rate != local.clock_rate {
				continue
			}
			out << Codec{
				payload_type:  candidate.payload_type
				name:          candidate.name
				clock_rate:    candidate.clock_rate
				channels:      candidate.channels
				fmtp:          candidate.fmtp
				rtcp_feedback: candidate.rtcp_feedback
			}
			break
		}
	}
	return out
}

// new_session_id returns the random identifier for the `o=` line.
fn new_session_id() !u64 {
	// RFC 8866 wants a value unlikely to collide with any other session. The
	// top bit is cleared because the field is written as a decimal integer and
	// several stacks read it into a signed 64-bit type.
	return randutil.next_u64()! >> 1
}
