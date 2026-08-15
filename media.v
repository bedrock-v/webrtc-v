module webrtc

import sync
import time
import webrtc.dtls
import webrtc.ice
import webrtc.logging
import webrtc.rtp
import webrtc.rtcp
import webrtc.srtp

// Media over the same socket the handshake used.
//
// WebRTC multiplexes DTLS, RTP and RTCP onto one ICE transport, so something
// has to look at each datagram and decide where it goes. RFC 7983 fixes that by
// the first byte: 20-63 is DTLS, 128-191 is RTP or RTCP, and within that the
// payload type separates the two. MediaTransport does the demultiplexing, hands
// DTLS to the handshake and protects everything else with the keys the
// handshake exported.

// media_queue_depth bounds how many packets may wait to be read. A reader that
// stops reading must not be able to make us buffer without limit, so the
// oldest packet is dropped instead - which is also the right thing for
// real-time media, where a late packet is worth less than a fresh one.
const media_queue_depth = 256

// MediaTransport carries RTP and RTCP for a connection.
pub struct MediaTransport {
mut:
	agent &ice.Agent = unsafe { nil }
	log   logging.Logger

	dtls_datagrams chan []u8 = chan []u8{cap: 64}
	rtp_packets    chan []u8 = chan []u8{cap: media_queue_depth}
	rtcp_packets   chan []u8 = chan []u8{cap: media_queue_depth}

	// keys_mu guards the two contexts. An srtp.Context is not safe for
	// concurrent use, and the application may send from any thread while the
	// pump receives.
	keys_mu  &sync.Mutex   = sync.new_mutex()
	outbound &srtp.Context = unsafe { nil }
	inbound  &srtp.Context = unsafe { nil }

	closed_mu &sync.Mutex = sync.new_mutex()
	closed    bool
	pump      ?thread
}

// MediaTransport.new starts demultiplexing the agent's datagrams.
fn MediaTransport.new(mut agent ice.Agent, log logging.Logger) &MediaTransport {
	mut transport := &MediaTransport{
		agent: agent
		log:   log.with_scope('media')
	}
	transport.pump = spawn transport.run()
	return transport
}

// send passes a DTLS record through untouched, satisfying dtls.Transport.
fn (mut m MediaTransport) send(data []u8) !int {
	mut agent := m.agent
	return agent.send(data)
}

// recv returns the next DTLS datagram, satisfying dtls.Transport.
fn (mut m MediaTransport) recv(timeout time.Duration) ![]u8 {
	select {
		datagram := <-m.dtls_datagrams {
			return datagram
		}
		timeout {
			return PeerError{
				reason: .timed_out
				detail: 'no DTLS datagram within ${timeout.milliseconds()}ms'
			}
		}
	}
	return PeerError{
		reason: .closed
		detail: 'the media transport is closed'
	}
}