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

fn (mut m MediaTransport) send_rtp_raw(raw []u8) ! {
	m.keys_mu.lock()
	mut context := m.outbound
	protected := if context == unsafe { nil } {
		[]u8{}
	} else {
		context.protect_rtp(raw) or {
			m.keys_mu.unlock()
			return PeerError{
				reason: .transport
				detail: 'protecting the RTP packet: ${err.msg()}'
			}
		}
	}
	m.keys_mu.unlock()

	if protected.len == 0 {
		return PeerError{
			reason: .no_media
			detail: 'the SRTP keys are not established yet'
		}
	}
	mut agent := m.agent
	agent.send(protected) or { return PeerError{
		reason: .transport
		detail: err.msg()
	} }
}

// send_rtcp protects and sends a compound RTCP packet.
fn (mut m MediaTransport) send_rtcp(packets []rtcp.Packet) ! {
	raw := rtcp.marshal(packets) or {
		return PeerError{
			reason: .transport
			detail: 'encoding the RTCP packet: ${err.msg()}'
		}
	}

	m.keys_mu.lock()
	mut context := m.outbound
	protected := if context == unsafe { nil } {
		[]u8{}
	} else {
		context.protect_rtcp(raw) or {
			m.keys_mu.unlock()
			return PeerError{
				reason: .transport
				detail: 'protecting the RTCP packet: ${err.msg()}'
			}
		}
	}
	m.keys_mu.unlock()

	if protected.len == 0 {
		return PeerError{
			reason: .no_media
			detail: 'the SRTP keys are not established yet'
		}
	}
	mut agent := m.agent
	agent.send(protected) or { return PeerError{
		reason: .transport
		detail: err.msg()
	} }
}

// recv_rtp returns the next RTP packet, decrypted.
//
// A packet that fails authentication is dropped and the wait continues: over a
// public transport anyone can inject bytes, and letting that surface as an
// error would let them stop a receiver from reading.
fn (mut m MediaTransport) recv_rtp(timeout time.Duration) !rtp.Packet {
	deadline := time.now().add(timeout)
	for {
		remaining := deadline - time.now()
		if remaining <= 0 {
			return PeerError{
				reason: .timed_out
				detail: 'no RTP packet within ${timeout.milliseconds()}ms'
			}
		}
		raw := m.next(m.rtp_packets, remaining)!
		plaintext := m.unprotect_rtp(raw) or { continue }
		packet := rtp.Packet.decode(plaintext) or {
			m.log.debug('dropped an undecodable RTP packet: ${err.msg()}')
			continue
		}
		return packet
	}
	return PeerError{
		reason: .closed
		detail: 'the media transport is closed'
	}
}

// recv_rtcp returns the next RTCP compound packet, decrypted and parsed.
fn (mut m MediaTransport) recv_rtcp(timeout time.Duration) ![]rtcp.Packet {
	deadline := time.now().add(timeout)
	for {
		remaining := deadline - time.now()
		if remaining <= 0 {
			return PeerError{
				reason: .timed_out
				detail: 'no RTCP packet within ${timeout.milliseconds()}ms'
			}
		}
		raw := m.next(m.rtcp_packets, remaining)!
		plaintext := m.unprotect_rtcp(raw) or { continue }
		packets := rtcp.unmarshal(plaintext) or {
			m.log.debug('dropped an undecodable RTCP packet: ${err.msg()}')
			continue
		}
		return packets
	}
	return PeerError{
		reason: .closed
		detail: 'the media transport is closed'
	}
}

fn (mut m MediaTransport) unprotect_rtp(raw []u8) ?[]u8 {
	m.keys_mu.lock()
	defer {
		m.keys_mu.unlock()
	}
	mut context := m.inbound
	if context == unsafe { nil } {
		return none
	}
	return context.unprotect_rtp(raw) or {
		m.log.debug('dropped an unauthenticated RTP packet: ${err.msg()}')
		none
	}
}

fn (mut m MediaTransport) unprotect_rtcp(raw []u8) ?[]u8 {
	m.keys_mu.lock()
	defer {
		m.keys_mu.unlock()
	}
	mut context := m.inbound
	if context == unsafe { nil } {
		return none
	}
	return context.unprotect_rtcp(raw) or {
		m.log.debug('dropped an unauthenticated RTCP packet: ${err.msg()}')
		none
	}
}

fn (mut m MediaTransport) next(queue chan []u8, timeout time.Duration) ![]u8 {
	select {
		datagram := <-queue {
			if datagram.len == 0 && m.is_closed() {
				// A receive on a closed channel succeeds with the zero value in
				// V 0.5.2, and an empty datagram is never a real packet.
				return PeerError{
					reason: .closed
					detail: 'the media transport is closed'
				}
			}
			return datagram
		}
		timeout {
			return PeerError{
				reason: .timed_out
				detail: 'nothing to read within ${timeout.milliseconds()}ms'
			}
		}
	}
	return PeerError{
		reason: .closed
		detail: 'the media transport is closed'
	}
}

fn (mut m MediaTransport) is_closed() bool {
	m.closed_mu.lock()
	defer {
		m.closed_mu.unlock()
	}
	return m.closed
}

// close stops the pump and releases the queues.
fn (mut m MediaTransport) close() {
	m.closed_mu.lock()
	if m.closed {
		m.closed_mu.unlock()
		return
	}
	m.closed = true
	m.closed_mu.unlock()

	m.dtls_datagrams.close()
	m.rtp_packets.close()
	m.rtcp_packets.close()
	if handle := m.pump {
		handle.wait()
		m.pump = none
	}
}

// attach_media keys the media transport from the finished handshake.
fn (mut pc PeerConnection) attach_media(mut conn dtls.Conn) ! {
	pc.mu.lock()
	mut transport := pc.media_transport
	pc.mu.unlock()
	if transport == unsafe { nil } {
		return PeerError{
			reason: .no_media
			detail: 'there is no media transport on this connection'
		}
	}

	mut outbound, mut inbound := conn.srtp_contexts() or {
		return PeerError{
			reason: .no_media
			detail: 'no SRTP keys: ${err.msg()}'
		}
	}
	transport.attach(mut outbound, mut inbound)
	pc.log.debug('SRTP keyed with ${outbound.profile()}')
}

// send_rtp sends one RTP packet to the peer.
pub fn (mut pc PeerConnection) send_rtp(packet rtp.Packet) ! {
	mut transport := pc.media()!
	transport.send_rtp(packet)!
}

// send_rtcp sends a compound RTCP packet to the peer.
pub fn (mut pc PeerConnection) send_rtcp(packets []rtcp.Packet) ! {
	mut transport := pc.media()!
	transport.send_rtcp(packets)!
}

// recv_rtp returns the next RTP packet from the peer.
pub fn (mut pc PeerConnection) recv_rtp(timeout time.Duration) !rtp.Packet {
	mut transport := pc.media()!
	return transport.recv_rtp(timeout)
}

// recv_rtcp returns the next RTCP compound packet from the peer.
pub fn (mut pc PeerConnection) recv_rtcp(timeout time.Duration) ![]rtcp.Packet {
	mut transport := pc.media()!
	return transport.recv_rtcp(timeout)
}

fn (mut pc PeerConnection) media() !&MediaTransport {
	pc.mu.lock()
	mut transport := pc.media_transport
	closed := pc.closed
	pc.mu.unlock()
	if closed {
		return PeerError{
			reason: .closed
			detail: 'the connection is closed'
		}
	}
	if transport == unsafe { nil } {
		return PeerError{
			reason: .no_media
			detail: 'no media section was negotiated'
		}
	}
	return transport
}
