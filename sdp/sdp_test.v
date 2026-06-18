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

fn test_direction() {
	s := parse_offer()!
	assert s.media_descriptions[0].direction() == .sendrecv
	assert s.media_descriptions[1].direction() == .sendonly
	// The data section carries no direction attribute.
	assert s.media_descriptions[2].direction() == .unspecified
}

fn test_direction_reverse() {
	assert Direction.sendonly.reverse() == .recvonly
	assert Direction.recvonly.reverse() == .sendonly
	assert Direction.sendrecv.reverse() == .sendrecv
	assert Direction.inactive.reverse() == .inactive
	assert Direction.unspecified.reverse() == .unspecified
}

fn test_ice_credentials_and_options() {
	s := parse_offer()!
	audio := s.media_descriptions[0]
	assert s.ice_ufrag(audio)? == '4ZcD'
	assert s.ice_pwd(audio)? == '2/1muCWoOi3uLifh0NuRHlZw'
	assert s.ice_options(audio) == ['trickle']
	// The video section has no ice-options of its own and none at session
	// level, so the list is empty rather than inherited from a sibling.
	assert s.ice_options(s.media_descriptions[1]) == []
}

fn test_ice_credentials_fall_back_to_session_level() {
	doc := 'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n' + 'a=ice-ufrag:SESS\r\n' +
		'a=ice-pwd:sessionpassword0123456789\r\n' + 'a=ice-options:trickle\r\n' +
		'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n' + 'a=mid:0\r\n'
	s := parse(doc)!
	media := s.media_descriptions[0]
	assert s.ice_ufrag(media)? == 'SESS'
	assert s.ice_pwd(media)? == 'sessionpassword0123456789'
	assert s.ice_options(media) == ['trickle']
}

fn test_fingerprints_and_setup() {
	s := parse_offer()!
	audio := s.media_descriptions[0]
	prints := s.fingerprints(audio)
	assert prints.len == 1
	assert prints[0].algorithm == 'sha-256'
	assert prints[0].value.starts_with('75:74:5a')
	assert s.setup(audio)? == .actpass
}

fn test_setup_answer_roles() {
	// RFC 5763: an answerer that receives actpass becomes the DTLS client.
	assert Setup.actpass.answer() == .active
	assert Setup.active.answer() == .passive
	assert Setup.passive.answer() == .active
	assert Setup.holdconn.answer() == .holdconn
	assert setup_from_string('nonsense') == none
}

fn test_rtpmap_and_fmtp() {
	s := parse_offer()!
	audio := s.media_descriptions[0]

	opus := audio.rtpmap(111)?
	assert opus.encoding_name == 'opus'
	assert opus.clock_rate == 48000
	assert opus.encoding_params == '2'
	assert opus.str() == '111 opus/48000/2'

	pcmu := audio.rtpmap(0)?
	assert pcmu.encoding_name == 'PCMU'
	assert pcmu.clock_rate == 8000
	assert pcmu.encoding_params == ''

	assert audio.fmtp(111)? == 'minptime=10;useinbandfec=1'
	assert audio.fmtp(0) == none
	assert audio.rtpmaps().len == 8

	video := s.media_descriptions[1]
	assert video.fmtp(97)? == 'apt=96'
}

fn test_rtcp_feedback() {
	s := parse_offer()!
	video := s.media_descriptions[1]
	fb := video.rtcp_feedback()
	assert fb.len == 4

	assert fb[0].payload_type == 96
	assert fb[0].typ == 'goog-remb'
	assert fb[0].parameter == ''
	assert !fb[0].wildcard

	assert fb[2].typ == 'nack'
	assert fb[2].parameter == 'pli'

	assert fb[3].wildcard
	assert fb[3].typ == 'ccm'
	assert fb[3].parameter == 'fir'
	assert fb[3].str() == '* ccm fir'
}

fn test_extmaps() {
	s := parse_offer()!
	audio_ext := s.media_descriptions[0].extmaps()
	assert audio_ext.len == 2
	assert audio_ext[0].id == 1
	assert audio_ext[0].uri == 'urn:ietf:params:rtp-hdrext:ssrc-audio-level'
	assert audio_ext[0].direction == .unspecified

	video_ext := s.media_descriptions[1].extmaps()
	assert video_ext[0].id == 2
	assert video_ext[0].direction == .sendonly
	assert video_ext[0].str() == '2/sendonly urn:ietf:params:rtp-hdrext:toffset'
}

fn test_extmap_rejects_invalid_ids() {
	doc := 'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n' +
		'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n' + 'a=extmap:0 urn:zero\r\n' +
		'a=extmap:256 urn:too-big\r\n' + 'a=extmap:not-a-number urn:bad\r\n' +
		'a=extmap:5 urn:fine\r\n'
	s := parse(doc)!
	extmaps := s.media_descriptions[0].extmaps()
	assert extmaps.len == 1
	assert extmaps[0].id == 5
}

fn test_ssrcs_and_groups() {
	s := parse_offer()!
	audio_ssrcs := s.media_descriptions[0].ssrcs()
	assert audio_ssrcs.len == 2
	assert audio_ssrcs[0].ssrc == 1001
	assert audio_ssrcs[0].attribute == 'cname'
	assert audio_ssrcs[0].value == 'cname-value'
	assert audio_ssrcs[1].attribute == 'msid'
	assert audio_ssrcs[1].value == 'stream-id audio-track-id'

	groups := s.media_descriptions[1].ssrc_groups()
	assert groups.len == 1
	assert groups[0].semantics == 'FID'
	assert groups[0].ssrcs == [u32(2001), 2002]
}

fn test_msid() {
	s := parse_offer()!
	msid := s.media_descriptions[0].msid()?
	assert msid.stream_id == 'stream-id'
	assert msid.track_id == 'audio-track-id'
	assert msid.str() == 'stream-id audio-track-id'
	assert s.media_descriptions[2].msid() == none
}

fn test_mux_flags_and_candidates() {
	s := parse_offer()!
	assert s.media_descriptions[0].uses_rtcp_mux()
	assert !s.media_descriptions[0].uses_rtcp_rsize()
	assert s.media_descriptions[1].uses_rtcp_rsize()

	video := s.media_descriptions[1]
	assert video.candidates() == ['1 1 udp 2113937151 192.168.1.10 54321 typ host']
	assert video.has_end_of_candidates()
	assert !s.media_descriptions[0].has_end_of_candidates()
}

fn test_sctp_attributes() {
	s := parse_offer()!
	data := s.media_descriptions[2]
	assert data.sctp_port()? == 5000
	assert data.max_message_size()? == 262144
	assert s.media_descriptions[0].sctp_port() == none
}

fn test_bandwidth_and_connection() {
	s := parse_offer()!
	video := s.media_descriptions[1]
	assert video.bandwidth.len == 1
	assert video.bandwidth[0].typ == 'AS'
	assert video.bandwidth[0].value == 2000

	conn := video.connection?
	assert conn.network_type == 'IN'
	assert conn.address_type == 'IP4'
	assert conn.address == '0.0.0.0'
}

fn test_round_trip_is_stable() {
	s := parse_offer()!
	once := s.marshal()
	twice := parse(once)!.marshal()
	assert once == twice

	// Every attribute survives, including the ones this package has no typed
	// accessor for.
	assert once.contains('a=extmap-allow-mixed')
	assert once.contains('a=msid-semantic: WMS stream-id')
	assert once.contains('a=rtcp:9 IN IP4 0.0.0.0')
	assert once.contains('a=end-of-candidates')
}

fn test_round_trip_preserves_unknown_attributes() {
	doc := 'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n' +
		'a=x-vendor-session:something\r\n' + 'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n' +
		'a=x-vendor-media:other\r\n' + 'a=x-flag\r\n'
	assert parse(doc)!.marshal() == doc
}