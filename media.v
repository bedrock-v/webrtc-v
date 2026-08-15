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

// run reads the socket and sorts what arrives.
fn (mut m MediaTransport) run() {
	for {
		if m.is_closed() {
			return
		}
		mut agent := m.agent
		datagram := agent.recv(100 * time.millisecond) or {
			if err is ice.AgentError && err.reason == .closed {
				return
			}
			continue
		}
		if datagram.len == 0 {
			continue
		}

		first := datagram[0]
		match true {
			// RFC 7983: DTLS occupies 20-63, which is where the record content
			// types live.
			first >= 20 && first <= 63 {
				m.offer_to(m.dtls_datagrams, datagram)
			}
			first >= 128 && first <= 191 {
				if rtp.is_rtcp_payload_type(datagram) {
					m.offer_to(m.rtcp_packets, datagram)
				} else {
					m.offer_to(m.rtp_packets, datagram)
				}
			}
			else {
				// STUN is handled inside the agent, and 64-127 is unassigned.
				// Anything here is not ours.
				m.log.debug('dropped a datagram with a first byte of ${first}')
			}
		}
	}
}

// offer_to queues a datagram, dropping the oldest if the reader has fallen
// behind.
fn (mut m MediaTransport) offer_to(queue chan []u8, datagram []u8) {
	select {
		queue <- datagram {
			return
		}
		else {}
	}
	// The queue is full. Discard one packet from the front and try once more;
	// if that also fails the reader is gone and the packet is dropped.
	select {
		_ := <-queue {}
		else {
			return
		}
	}
	select {
		queue <- datagram {}
		else {}
	}
}

// attach installs the keys the DTLS handshake exported.
fn (mut m MediaTransport) attach(mut outbound srtp.Context, mut inbound srtp.Context) {
	m.keys_mu.lock()
	m.outbound = outbound
	m.inbound = inbound
	m.keys_mu.unlock()
}

fn (mut m MediaTransport) is_keyed() bool {
	m.keys_mu.lock()
	defer {
		m.keys_mu.unlock()
	}
	return m.outbound != unsafe { nil }
}

// send_rtp protects and sends one RTP packet.
fn (mut m MediaTransport) send_rtp(packet rtp.Packet) ! {
	raw := packet.marshal() or {
		return PeerError{
			reason: .transport
			detail: 'encoding the RTP packet: ${err.msg()}'
		}
	}
	m.send_rtp_raw(raw)!
}