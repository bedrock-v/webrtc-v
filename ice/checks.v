module ice

import time
import webrtc.netaddr
import webrtc.stun
import webrtc.transport
import webrtc.turn

// start launches the reader threads and the agent loop. The caller must not
// hold the mutex.
fn (mut a Agent) start() {
	a.mu.lock()
	if a.closed || a.threads.len > 0 {
		a.mu.unlock()
		return
	}
	count := a.sockets.len
	a.mu.unlock()

	for i in 0 .. count {
		a.threads << spawn a.read_socket(i)
	}
	a.threads << spawn a.run()
}

// read_socket forwards datagrams from one socket to the agent loop.
//
// This thread does no parsing and holds no locks. Everything it reads goes into
// a channel, so the ordering rules that ICE depends on are enforced in exactly
// one place - the agent loop - rather than racing across one thread per socket.
fn (mut a Agent) read_socket(index int) {
	a.mu.lock()
	if index >= a.sockets.len {
		a.mu.unlock()
		return
	}
	mut socket := a.sockets[index]
	a.mu.unlock()

	if socket.relay != unsafe { nil } {
		a.read_relay(index, mut socket.relay)
		return
	}

	mut conn := socket.conn
	for {
		if a.is_closed() {
			return
		}
		// A read timeout, rather than a blocking read, is what lets this thread
		// notice that the agent has been closed.
		conn.set_read_timeout(200 * time.millisecond)
		mut buf := []u8{len: max_datagram}
		n, peer := conn.read(mut buf) or { continue }
		if n <= 0 {
			continue
		}
		from := transport.socket_addr_from_net(peer) or { continue }

		packet := InboundPacket{
			socket: index
			from:   from.unmap()
			data:   buf[..n].clone()
		}
		// A full queue means the agent loop is not keeping up. Dropping is the
		// only option that does not stall this reader, and UDP has no delivery
		// guarantee to violate: a lost check is retransmitted, and lost media
		// is lost either way.
		select {
			a.inbound <- packet {}
			else {
				a.log.warn('inbound queue full, dropped ${n} bytes from ${from}')
			}
		}
	}
}

// read_relay forwards what a TURN allocation hands back, in the same shape as a
// socket read so the agent loop cannot tell them apart.
fn (mut a Agent) read_relay(index int, mut relay turn.Client) {
	for {
		if a.is_closed() {
			return
		}
		packet := relay.recv(200 * time.millisecond) or {
			if err is turn.TurnError && err.reason == .closed {
				return
			}
			continue
		}
		inbound := InboundPacket{
			socket: index
			from:   packet.from.unmap()
			data:   packet.data
		}
		select {
			a.inbound <- inbound {}
			else {
				a.log.warn('inbound queue full, dropped ${packet.data.len} relayed bytes from ${packet.from}')
			}
		}
	}
}

// run is the agent loop. It owns every mutation of the check list.
fn (mut a Agent) run() {
	for {
		if a.is_closed() {
			return
		}
		select {
			packet := <-a.inbound {
				a.handle_packet(packet)
			}
			a.config.check_interval {
				a.tick()
			}
		}
	}
}

// is_closed reports whether the agent has been shut down.
fn (mut a Agent) is_closed() bool {
	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	return a.closed
}