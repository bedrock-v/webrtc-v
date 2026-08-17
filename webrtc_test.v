module webrtc

import time
import webrtc.dtls
import webrtc.logging
import webrtc.rtp
import webrtc.sdp

// Tests for the peer connection layer.
//
// The state machine tests are cheap and deterministic; the loopback test opens
// real sockets and runs the whole stack, which is the only way to know that the
// pieces agree with each other about roles, identifiers and timing.

fn test_a_connection_starts_stable_and_new() {
	mut pc := PeerConnection.new()!
	defer {
		pc.close()
	}
	assert pc.signaling_state() == .stable
	assert pc.connection_state() == .new
	assert pc.current_local_description() == none
	assert pc.current_remote_description() == none
	assert pc.local_fingerprint().algorithm == .sha256
}

fn test_an_offer_needs_something_to_offer() {
	mut pc := PeerConnection.new()!
	defer {
		pc.close()
	}
	if _ := pc.create_offer() {
		assert false, 'an empty connection should not produce an offer'
	} else {
		assert err is PeerError
		if err is PeerError {
			assert err.reason == .wrong_state
		}
	}
}

fn test_turn_servers_are_refused_rather_than_ignored() {
	if _ := PeerConnection.new(
		ice_servers: [IceServer{
			urls: ['turn:relay.example:3478']
		}]
	)
	{
		assert false, 'a TURN server should be refused while TURN is unimplemented'
	} else {
		assert err is PeerError
		if err is PeerError {
			assert err.reason == .unsupported
		}
	}
}

fn test_an_offer_describes_the_data_channel_section() {
	mut pc := PeerConnection.new()!
	defer {
		pc.close()
	}
	pc.create_data_channel('chat')!

	offer := pc.create_offer()!
	assert offer.typ == .offer
	assert offer.sdp.contains('m=application 9 UDP/DTLS/SCTP webrtc-datachannel')
	assert offer.sdp.contains('a=group:BUNDLE 0')
	assert offer.sdp.contains('a=setup:actpass')
	assert offer.sdp.contains('a=sctp-port:5000')
	assert offer.sdp.contains('a=fingerprint:sha-256 ')
	assert offer.sdp.contains('a=ice-ufrag:')
	assert offer.sdp.contains('a=max-message-size:')
}

fn test_an_offer_describes_media_sections() {
	mut pc := PeerConnection.new()!
	defer {
		pc.close()
	}
	pc.add_media(.audio, .sendrecv, [opus_48000_2])!
	pc.add_media(.video, .sendonly, [vp8_90000])!

	offer := pc.create_offer()!
	assert offer.sdp.contains('m=audio 9 UDP/TLS/RTP/SAVPF 111')
	assert offer.sdp.contains('a=rtpmap:111 opus/48000/2')
	assert offer.sdp.contains('a=fmtp:111 minptime=10;useinbandfec=1')
	assert offer.sdp.contains('a=sendrecv')
	assert offer.sdp.contains('m=video 9 UDP/TLS/RTP/SAVPF 96')
	assert offer.sdp.contains('a=rtpmap:96 VP8/90000')
	assert offer.sdp.contains('a=rtcp-fb:96 nack pli')
	assert offer.sdp.contains('a=sendonly')
	assert offer.sdp.contains('a=rtcp-mux')
	assert offer.sdp.contains('a=group:BUNDLE 0 1')
}

fn test_media_cannot_be_added_after_the_offer() {
	mut pc := PeerConnection.new()!
	defer {
		pc.close()
	}
	pc.add_media(.audio, .sendrecv, [opus_48000_2])!
	offer := pc.create_offer()!
	pc.set_local_description(offer)!

	if _ := pc.add_media(.video, .sendrecv, [vp8_90000]) {
		assert false, 'renegotiation is not implemented and should be refused'
	} else {
		assert err is PeerError
	}
}

fn test_the_answerer_mirrors_the_sections() {
	mut offerer := PeerConnection.new()!
	mut answerer := PeerConnection.new()!
	defer {
		offerer.close()
		answerer.close()
	}
	offerer.add_media(.audio, .sendrecv, [opus_48000_2])!
	offerer.create_data_channel('chat')!
	answerer.add_media(.audio, .sendrecv, [opus_48000_2])!

	offer := offerer.create_offer()!
	answerer.set_remote_description(offer)!
	assert answerer.signaling_state() == .have_remote_offer

	answer := answerer.create_answer()!
	assert answer.typ == .answer
	// The offer said actpass, so the answerer picks active and starts the
	// handshake itself.
	assert answer.sdp.contains('a=setup:active')
	assert answer.sdp.contains('m=audio 9 UDP/TLS/RTP/SAVPF 111')
	assert answer.sdp.contains('m=application 9 UDP/DTLS/SCTP webrtc-datachannel')
	assert answer.sdp.contains('a=group:BUNDLE 0 1')
}

fn test_a_section_with_no_common_codec_is_rejected() {
	mut offerer := PeerConnection.new()!
	mut answerer := PeerConnection.new()!
	defer {
		offerer.close()
		answerer.close()
	}
	offerer.add_media(.video, .sendrecv, [vp8_90000])!
	// The answerer only does audio, so the video section has to come back with a
	// port of zero rather than be left out.
	answerer.add_media(.audio, .sendrecv, [opus_48000_2])!

	offer := offerer.create_offer()!
	answerer.set_remote_description(offer)!
	answer := answerer.create_answer()!
	assert answer.sdp.contains('m=video 0 ')
	assert !answer.sdp.contains('a=rtpmap:96')
}

fn test_the_answerer_keeps_the_offered_payload_types() {
	// A peer that numbers opus 100 must get 100 back: the payload types are the
	// offerer's to assign.
	offered := [
		Codec{
			payload_type: 100
			name:         'opus'
			clock_rate:   48000
			channels:     2
		},
	]
	supported := [opus_48000_2]
	intersection := intersect_codecs(offered, supported)
	assert intersection.len == 1
	assert intersection[0].payload_type == 100
}

fn test_a_description_without_ice_credentials_is_refused() {
	text := 'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n' +
		'm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n'
	if _ := parse_remote_description(text) {
		assert false, 'a description with no ICE credentials should be refused'
	} else {
		assert err is PeerError
		if err is PeerError {
			assert err.reason == .bad_description
		}
	}
}

fn test_a_description_without_a_fingerprint_is_refused() {
	// Without a fingerprint there is nothing to bind the DTLS handshake to, so
	// the peer could be anyone who answered.
	text := 'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n' +
		'm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\n' +
		'a=ice-ufrag:abcd\r\na=ice-pwd:0123456789012345678901\r\na=mid:0\r\n'
	if _ := parse_remote_description(text) {
		assert false, 'a description with no fingerprint should be refused'
	} else {
		assert err is PeerError
		if err is PeerError {
			assert err.reason == .bad_description
		}
	}
}

fn test_an_answer_may_not_leave_the_roles_undetermined() {
	mut offerer := PeerConnection.new()!
	mut answerer := PeerConnection.new()!
	defer {
		offerer.close()
		answerer.close()
	}
	offerer.create_data_channel('chat')!
	offer := offerer.create_offer()!
	offerer.set_local_description(offer)!

	answerer.set_remote_description(offer)!
	answer := answerer.create_answer()!
	// Both ends would wait for the other to start the handshake.
	broken := SessionDescription{
		typ: .answer
		sdp: answer.sdp.replace('a=setup:active', 'a=setup:actpass')
	}
	if _ := offerer.set_remote_description(broken) {
		assert false, 'an actpass answer should be refused'
	} else {
		assert err is PeerError
		if err is PeerError {
			assert err.reason == .bad_description
		}
	}
}

fn test_an_answer_cannot_be_applied_without_an_offer() {
	mut pc := PeerConnection.new()!
	defer {
		pc.close()
	}
	pc.create_data_channel('chat')!
	offer := pc.create_offer()!
	if _ := pc.set_remote_description(SessionDescription{ typ: .answer, sdp: offer.sdp }) {
		assert false, 'an answer needs a local offer first'
	} else {
		assert err is PeerError
		if err is PeerError {
			assert err.reason == .wrong_state
		}
	}
}

fn test_a_candidate_cannot_be_added_before_a_local_description() {
	mut pc := PeerConnection.new()!
	defer {
		pc.close()
	}
	if _ := pc.add_ice_candidate('candidate:1 1 udp 2130706431 127.0.0.1 4000 typ host') {
		assert false, 'there is nothing to add a candidate to yet'
	} else {
		assert err is PeerError
		if err is PeerError {
			assert err.reason == .wrong_state
		}
	}
}

fn test_a_closed_connection_refuses_work() {
	mut pc := PeerConnection.new()!
	pc.create_data_channel('chat')!
	pc.close()

	assert pc.connection_state() == .closed
	assert pc.signaling_state() == .closed
	if _ := pc.create_offer() {
		assert false, 'a closed connection should not produce an offer'
	} else {
		assert err is PeerError
		if err is PeerError {
			assert err.reason == .closed
		}
	}
	// Closing twice is what a deferred close plus an explicit one does.
	pc.close()
}

fn test_media_calls_fail_without_a_media_section() {
	mut pc := PeerConnection.new()!
	defer {
		pc.close()
	}
	if _ := pc.recv_rtp(10 * time.millisecond) {
		assert false, 'there is no media section to receive on'
	} else {
		assert err is PeerError
		if err is PeerError {
			assert err.reason == .no_media
		}
	}
}

fn test_a_channel_created_before_negotiation_is_connecting() {
	mut pc := PeerConnection.new()!
	defer {
		pc.close()
	}
	mut channel := pc.create_data_channel('chat')!
	assert channel.label == 'chat'
	assert channel.state() == .connecting
	assert channel.ordered()
	assert channel.reliable()
	assert channel.id() == none

	if _ := channel.send_text('too early') {
		assert false, 'a channel that is not open should refuse to send'
	} else {
		assert err is PeerError
	}
}

fn test_the_setup_role_decides_which_end_is_the_dtls_client() {
	mut offerer := PeerConnection.new()!
	mut answerer := PeerConnection.new()!
	defer {
		offerer.close()
		answerer.close()
	}
	offerer.create_data_channel('chat')!
	offer := offerer.create_offer()!
	answerer.set_remote_description(offer)!

	// The answerer chose active, so it is the DTLS client and the offerer is
	// the server. Both ends must reach the same conclusion or the handshake
	// never starts.
	assert answerer.role == dtls.Role.client
}