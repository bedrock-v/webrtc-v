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