// Parse a browser offer and print what it describes.
//
// Run with: v run examples/sdp-parse
module main

import webrtc.sdp

// A representative offer: one audio section and one data channel section,
// bundled onto a single transport. Written with plain newlines and converted on
// use, because SDP requires CRLF and an escaped literal is unreadable.
const offer = '
v=0
o=- 4611731400430051336 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0 1
a=msid-semantic: WMS stream-id
m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8
c=IN IP4 0.0.0.0
a=ice-ufrag:4ZcD
a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZw
a=ice-options:trickle
a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24
a=setup:actpass
a=mid:0
a=sendrecv
a=rtcp-mux
a=rtpmap:111 opus/48000/2
a=fmtp:111 minptime=10;useinbandfec=1
a=rtcp-fb:111 transport-cc
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=ssrc:1001 cname:cname-value
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=ice-ufrag:4ZcD
a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZw
a=setup:actpass
a=mid:1
a=sctp-port:5000
a=max-message-size:262144
'.trim_left('\n').replace('\n',
	'\r\n')

fn main() {
	session := sdp.parse(offer)!

	println('session "${session.session_name}" from ${session.origin.unicast_address}')
	for group in session.bundle_groups() {
		println('bundle: ${group.join(', ')}')
	}
	println('')

	for media in session.media_descriptions {
		mid := media.mid() or { '?' }
		println('${media.media} (mid ${mid}) over ${media.proto()}')
		println('  direction: ${media.direction()}')

		if ufrag := session.ice_ufrag(media) {
			println('  ice-ufrag: ${ufrag}')
		}
		options := session.ice_options(media)
		if options.len > 0 {
			println('  ice-options: ${options.join(', ')}')
		}
		for fingerprint in session.fingerprints(media) {
			println('  fingerprint: ${fingerprint.algorithm} ${fingerprint.value[..23]}...')
		}
		if setup := session.setup(media) {
			println('  setup: ${setup} (we would answer ${setup.answer()})')
		}
		if media.uses_rtcp_mux() {
			println('  rtcp-mux: yes')
		}

		for codec in media.rtpmaps() {
			mut line := '  codec ${codec.payload_type}: ${codec.encoding_name}/${codec.clock_rate}'
			if codec.encoding_params != '' {
				line += '/${codec.encoding_params}'
			}
			if params := media.fmtp(codec.payload_type) {
				line += '  [${params}]'
			}
			println(line)
		}
		for feedback in media.rtcp_feedback() {
			println('  feedback: ${feedback}')
		}
		for ssrc in media.ssrcs() {
			println('  ssrc ${ssrc.ssrc}: ${ssrc.attribute}=${ssrc.value}')
		}
		if port := media.sctp_port() {
			size := media.max_message_size() or { 0 }
			println('  sctp port ${port}, messages up to ${size} bytes')
		}
		println('')
	}

	// Re-serialising is lossless, including the attributes this program never
	// looked at.
	if session.marshal() == offer {
		println('re-serialised byte for byte')
	}
}
