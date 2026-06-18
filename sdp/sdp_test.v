module sdp

// A representative offer of the shape a browser produces: one bundled audio
// section, one video section and one data channel section.
const browser_offer_lines = [
	'v=0',
	'o=- 4611731400430051336 2 IN IP4 127.0.0.1',
	's=-',
	't=0 0',
	'a=group:BUNDLE 0 1 2',
	'a=extmap-allow-mixed',
	'a=msid-semantic: WMS stream-id',
	'm=audio 9 UDP/TLS/RTP/SAVPF 111 63 9 0 8 13 110 126',
	'c=IN IP4 0.0.0.0',
	'a=rtcp:9 IN IP4 0.0.0.0',
	'a=ice-ufrag:4ZcD',
	'a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZw',
	'a=ice-options:trickle',
	'a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24',
	'a=setup:actpass',
	'a=mid:0',
	'a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level',
	'a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01',
	'a=sendrecv',
	'a=msid:stream-id audio-track-id',
	'a=rtcp-mux',
	'a=rtpmap:111 opus/48000/2',
	'a=rtcp-fb:111 transport-cc',
	'a=fmtp:111 minptime=10;useinbandfec=1',
	'a=rtpmap:63 red/48000/2',
	'a=fmtp:63 111/111',
	'a=rtpmap:9 G722/8000',
	'a=rtpmap:0 PCMU/8000',
	'a=rtpmap:8 PCMA/8000',
	'a=rtpmap:13 CN/8000',
	'a=rtpmap:110 telephone-event/48000',
	'a=rtpmap:126 telephone-event/8000',
	'a=ssrc:1001 cname:cname-value',
	'a=ssrc:1001 msid:stream-id audio-track-id',
	'm=video 9 UDP/TLS/RTP/SAVPF 96 97 98',
	'c=IN IP4 0.0.0.0',
	'b=AS:2000',
	'a=ice-ufrag:4ZcD',
	'a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZw',
	'a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24',
	'a=setup:actpass',
	'a=mid:1',
	'a=extmap:2/sendonly urn:ietf:params:rtp-hdrext:toffset',
	'a=sendonly',
	'a=rtcp-mux',
	'a=rtcp-rsize',
	'a=rtpmap:96 VP8/90000',
	'a=rtcp-fb:96 goog-remb',
	'a=rtcp-fb:96 nack',
	'a=rtcp-fb:96 nack pli',
	'a=rtcp-fb:* ccm fir',
	'a=rtpmap:97 rtx/90000',
	'a=fmtp:97 apt=96',
	'a=rtpmap:98 VP9/90000',
	'a=ssrc-group:FID 2001 2002',
	'a=ssrc:2001 cname:cname-value',
	'a=ssrc:2002 cname:cname-value',
	'a=candidate:1 1 udp 2113937151 192.168.1.10 54321 typ host',
	'a=end-of-candidates',
	'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
	'c=IN IP4 0.0.0.0',
	'a=ice-ufrag:4ZcD',
	'a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZw',
	'a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24',
	'a=setup:actpass',
	'a=mid:2',
	'a=sctp-port:5000',
	'a=max-message-size:262144',
]

const browser_offer = browser_offer_lines.join('\r\n') + '\r\n'

fn parse_offer() !SessionDescription {
	return parse(browser_offer)!
}

fn test_parses_session_level_fields() {
	s := parse_offer()!
	assert s.version == 0
	assert s.origin.username == '-'
	assert s.origin.session_id == 4611731400430051336
	assert s.origin.session_version == 2
	assert s.origin.network_type == 'IN'
	assert s.origin.address_type == 'IP4'
	assert s.origin.unicast_address == '127.0.0.1'
	assert s.session_name == '-'
	assert s.time_descriptions.len == 1
	assert s.time_descriptions[0].start_time == 0
	assert s.time_descriptions[0].stop_time == 0
}

fn test_parses_media_sections() {
	s := parse_offer()!
	assert s.media_descriptions.len == 3

	audio := s.media_descriptions[0]
	assert audio.media == 'audio'
	assert audio.port == 9
	assert audio.protos == ['UDP', 'TLS', 'RTP', 'SAVPF']
	assert audio.proto() == 'UDP/TLS/RTP/SAVPF'
	assert audio.formats == ['111', '63', '9', '0', '8', '13', '110', '126']
	assert !audio.is_rejected()

	data := s.media_descriptions[2]
	assert data.media == 'application'
	assert data.proto() == 'UDP/DTLS/SCTP'
	assert data.formats == ['webrtc-datachannel']
}

fn test_bundle_group() {
	s := parse_offer()!
	groups := s.bundle_groups()
	assert groups.len == 1
	assert groups[0] == ['0', '1', '2']
}

fn test_mid_and_lookup() {
	s := parse_offer()!
	assert s.media_descriptions[0].mid()? == '0'
	assert s.media_descriptions[1].mid()? == '1'
	assert s.media_description('1')?.media == 'video'
	assert s.media_description('nonexistent') == none
}