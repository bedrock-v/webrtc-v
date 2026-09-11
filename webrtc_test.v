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

fn test_a_data_channel_carries_messages_over_real_sockets() {
	mut caller := PeerConnection.new(logger: quiet_logger())!
	mut callee := PeerConnection.new(logger: quiet_logger())!
	defer {
		caller.close()
		callee.close()
	}

	mut sender := caller.create_data_channel('chat')!
	negotiate(mut caller, mut callee)!

	caller.wait_connected(30 * time.second)!
	callee.wait_connected(30 * time.second)!

	mut receiver := callee.accept_data_channel(10 * time.second)!
	assert receiver.label == 'chat'

	for index in 0 .. 5 {
		sender.send_text('message ${index}')!
	}
	for index in 0 .. 5 {
		message := receiver.recv(5 * time.second)!
		assert message.is_string
		assert message.text() == 'message ${index}'
	}

	// Binary and text are distinguished by the payload protocol identifier, not
	// by the bytes, so an empty message of each kind must survive.
	sender.send_binary([]u8{len: 4096, init: u8(index & 0xff)})!
	binary := receiver.recv(5 * time.second)!
	assert !binary.is_string
	assert binary.data.len == 4096
	assert binary.data[100] == 100

	// The reply direction uses the same association from the other end.
	receiver.send_text('ack')!
	reply := sender.recv(5 * time.second)!
	assert reply.text() == 'ack'

	assert sender.state() == .open
	if _ := caller.selected_candidate_pair() {
	} else {
		assert false, 'a connected agent must have a selected pair'
	}
	if _ := caller.remote_certificate() {
	} else {
		assert false, 'a finished handshake must have the peer certificate'
	}
	assert caller.current_local_description()!.typ == .offer
	assert callee.current_local_description()!.typ == .answer
}

fn test_media_keys_are_established_over_real_sockets() {
	mut caller := PeerConnection.new(logger: quiet_logger())!
	mut callee := PeerConnection.new(logger: quiet_logger())!
	defer {
		caller.close()
		callee.close()
	}

	caller.add_media(.audio, .sendrecv, [opus_48000_2])!
	callee.add_media(.audio, .sendrecv, [opus_48000_2])!
	negotiate(mut caller, mut callee)!

	caller.wait_connected(30 * time.second)!
	callee.wait_connected(30 * time.second)!

	caller_profile := caller.selected_srtp_profile() or { panic('no SRTP profile on the caller') }
	callee_profile := callee.selected_srtp_profile() or { panic('no SRTP profile on the callee') }
	assert caller_profile == callee_profile

	// Both ends must have keyed SRTP before either sends, so the handshake is
	// given a moment to finish on the receiving side.
	mut receiver := callee.media()!
	for _ in 0 .. 100 {
		if receiver.is_keyed() {
			break
		}
		time.sleep(20 * time.millisecond)
	}
	assert receiver.is_keyed()

	packet := rtp_test_packet()
	caller.send_rtp(packet)!
	received := callee.recv_rtp(5 * time.second)!
	assert received.header.ssrc == packet.header.ssrc
	assert received.header.sequence_number == packet.header.sequence_number
	assert received.payload == packet.payload
}

// negotiate runs a complete offer/answer exchange, including candidates.
fn negotiate(mut caller PeerConnection, mut callee PeerConnection) ! {
	offer := caller.create_offer()!
	caller.set_local_description(offer)!
	callee.set_remote_description(offer)!

	answer := callee.create_answer()!
	callee.set_local_description(answer)!
	caller.set_remote_description(answer)!

	// Candidates are signalled after both descriptions are in place, which is
	// what a trickling application does.
	for line in caller.local_candidates() {
		callee.add_ice_candidate(line) or {}
	}
	for line in callee.local_candidates() {
		caller.add_ice_candidate(line) or {}
	}
}

fn rtp_test_packet() rtp.Packet {
	return rtp.Packet{
		header:  rtp.Header{
			payload_type:    111
			sequence_number: 4242
			timestamp:       160000
			ssrc:            0x1234abcd
		}
		payload: [u8(0x01), 0x02, 0x03, 0x04]
	}
}

fn quiet_logger() logging.Logger {
	// The tests are quiet unless WEBRTC_LOG_LEVEL asks otherwise, so a failing
	// run can be re-run with the transports talking.
	return logging.from_env('test')
}

fn test_the_direction_of_an_answer_is_the_mirror_of_the_offer() {
	mut offerer := PeerConnection.new()!
	mut answerer := PeerConnection.new()!
	defer {
		offerer.close()
		answerer.close()
	}
	offerer.add_media(.audio, .sendonly, [opus_48000_2])!
	answerer.add_media(.audio, .sendrecv, [opus_48000_2])!

	offer := offerer.create_offer()!
	answerer.set_remote_description(offer)!
	answer := answerer.create_answer()!
	// The offerer only sends, so the answerer can only receive.
	assert answer.sdp.contains('a=recvonly')
	assert sdp.Direction.sendonly.reverse() == sdp.Direction.recvonly
}

fn test_channel_parameters_are_readable_before_the_transports_come_up() {
	mut pc := PeerConnection.new()!
	defer {
		pc.close()
	}

	mut plain := pc.create_data_channel('chat')!
	assert plain.label == 'chat'
	assert plain.ordered()
	assert plain.reliable()
	assert !plain.negotiated()
	assert plain.protocol() == ''
	assert plain.id() == none

	mut agreed := pc.create_data_channel('agreed',
		negotiated: true
		id:         u16(42)
		protocol:   'nethernet'
	)!
	assert agreed.negotiated()
	assert agreed.protocol() == 'nethernet'

	mut lossy := pc.create_data_channel('lossy', max_retransmits: u16(0))!
	assert !lossy.reliable()
	assert !lossy.negotiated()
	assert lossy.protocol() == ''
}

fn test_channel_parameters_survive_the_open_handshake() {
	mut caller := PeerConnection.new(logger: quiet_logger())!
	mut callee := PeerConnection.new(logger: quiet_logger())!
	defer {
		caller.close()
		callee.close()
	}

	mut sender := caller.create_data_channel('chat', protocol: 'nethernet')!
	negotiate(mut caller, mut callee)!
	caller.wait_connected(30 * time.second)!
	callee.wait_connected(30 * time.second)!

	mut receiver := callee.accept_data_channel(10 * time.second)!
	assert receiver.label == 'chat'

	assert receiver.protocol() == 'nethernet'

	assert !receiver.negotiated()
	assert receiver.ordered()
	assert receiver.reliable()

	assert sender.protocol() == 'nethernet'
	assert !sender.negotiated()
	assert sender.id() != none
}

fn test_a_negotiated_channel_reports_from_the_live_channel() {
	mut caller := PeerConnection.new(logger: quiet_logger())!
	mut callee := PeerConnection.new(logger: quiet_logger())!
	defer {
		caller.close()
		callee.close()
	}

	// Both sides declare the same stream; neither opens it through DCEP.
	mut ours := caller.create_data_channel('agreed',
		negotiated: true
		id:         u16(42)
		protocol:   'nethernet'
	)!
	mut theirs := callee.create_data_channel('agreed',
		negotiated: true
		id:         u16(42)
		protocol:   'nethernet'
	)!
	negotiate(mut caller, mut callee)!
	caller.wait_connected(30 * time.second)!
	callee.wait_connected(30 * time.second)!

	mut sides := [ours, theirs]
	for mut side in sides {
		id := side.id() or {
			assert false, 'the negotiated channel was never bound to a live channel'
			return
		}
		assert id == 42
		assert side.state() == .open
		assert side.negotiated()
		assert side.protocol() == 'nethernet'
		assert side.ordered()
		assert side.reliable()
	}

	// Declaring the same id on both sides has to produce one channel.
	ours.send_text('agreed without a handshake')!
	message := theirs.recv(5 * time.second)!
	assert message.text() == 'agreed without a handshake'
}
