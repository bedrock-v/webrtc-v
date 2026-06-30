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

// tick advances the state machine: it retires timed-out checks, sends the next
// one, and maintains consent on the selected pair.
fn (mut a Agent) tick() {
	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	if a.closed {
		return
	}
	a.expire_checks()
	a.send_next_check()
	a.maintain_consent()
	a.evaluate_state()
}

// expire_checks retires checks that have gone unanswered for too long.
fn (mut a Agent) expire_checks() {
	now := time.now()
	mut expired := []string{}
	for key, check in a.pending {
		if now - check.sent_at < a.config.binding_timeout {
			continue
		}
		expired << key
		if check.pair_index >= a.pairs.len {
			continue
		}
		if a.pairs[check.pair_index].binding_requests >= a.config.max_binding_requests {
			a.pairs[check.pair_index].state = .failed
			a.log.debug('pair failed after ${a.config.max_binding_requests} checks: ${a.pairs[check.pair_index]}')
		} else {
			// Back to waiting so the pair is retried in priority order rather
			// than immediately, which keeps one dead pair from monopolising the
			// check pacing.
			a.pairs[check.pair_index].state = .waiting
		}
	}
	for key in expired {
		a.pending.delete(key)
	}
	if expired.len > 0 {
		a.unfreeze_by_foundation()
	}
}

// send_next_check probes the highest-priority pair that is waiting.
//
// One check per tick is what implements the Ta pacing of RFC 8445 section 14.2.
// Sending the whole check list at once would put a burst on the network that
// looks like a scan and competes with the media it is trying to enable.
fn (mut a Agent) send_next_check() {
	if a.remote_ufrag == '' || a.remote_pwd == '' {
		return
	}
	mut index := -1
	for i, pair in a.pairs {
		if pair.state == .waiting {
			index = i
			break
		}
	}
	if index < 0 {
		return
	}
	a.send_check(index, false)
}

// send_check sends one connectivity check for a pair.
fn (mut a Agent) send_check(index int, nominate bool) {
	if index < 0 || index >= a.pairs.len {
		return
	}
	pair := a.pairs[index]
	socket_index := a.socket_for[pair.local.address.str()] or {
		a.log.warn('no socket for local candidate ${pair.local.address}')
		a.pairs[index].state = .failed
		return
	}
	if socket_index >= a.sockets.len {
		return
	}

	mut request := stun.Message.new(.request, .binding) or { return }
	// RFC 8445 section 7.2.2: the username is the peer's fragment followed by
	// ours, so the receiver can tell which of its sessions the check belongs to
	// before it has verified anything.
	request.add_username('${a.remote_ufrag}:${a.local_ufrag}') or { return }
	request.add_priority(compute_priority(.peer_reflexive,
		default_local_preference(pair.local.address.ip), pair.local.component))
	if a.role == .controlling {
		request.add_ice_controlling(a.tiebreaker)
		if nominate {
			request.add_use_candidate()
		}
	} else {
		request.add_ice_controlled(a.tiebreaker)
	}

	// The check is keyed with the peer's password, which only the signalling
	// channel could have carried. That is what makes a connectivity check an
	// authentication as well as a reachability probe.
	key := stun.short_term_key(a.remote_pwd) or { return }
	raw := request.encode(integrity_key: key, fingerprint: true) or { return }

	a.transmit(socket_index, pair.remote.address, raw) or {
		a.log.debug('sending a check to ${pair.remote.address} failed: ${err.msg()}')
		a.pairs[index].state = .failed
		return
	}

	a.pairs[index].state = .in_progress
	a.pairs[index].binding_requests++
	a.pairs[index].last_sent = time.now()
	a.pending[request.transaction_id[..].hex()] = PendingCheck{
		pair_index: index
		sent_at:    time.now()
		nominating: nominate
	}
	a.log.trace('check #${a.pairs[index].binding_requests} to ${pair.remote.address}${if nominate {
		' (nominating)'
	} else {
		''
	}}')
}

// maintain_consent keeps the selected pair alive and notices when it dies.
//
// RFC 7675: a WebRTC endpoint must keep proving that the peer still wants the
// traffic. The same exchange doubles as a NAT keepalive, so stopping it loses
// the mapping as well as the consent.
fn (mut a Agent) maintain_consent() {
	if a.selected < 0 || a.selected >= a.pairs.len {
		return
	}
	now := time.now()
	pair := a.pairs[a.selected]

	if now - pair.last_sent >= a.config.keepalive_interval {
		a.send_check(a.selected, a.role == .controlling && !pair.nominated)
		// The pair is still the selected one; sending a check must not put it
		// back into the checking sequence.
		a.pairs[a.selected].state = .succeeded
	}
}

// evaluate_state derives the connection state from the check list.
fn (mut a Agent) evaluate_state() {
	if a.state == .closed || a.state == .failed {
		return
	}
	now := time.now()

	if a.selected >= 0 && a.selected < a.pairs.len {
		silence := now - a.pairs[a.selected].last_received
		if silence > a.config.failed_timeout {
			a.log.warn('no traffic on the selected pair for ${silence.seconds():.1f}s, giving up')
			a.selected = -1
			a.set_state(.failed)
			return
		}
		if silence > a.config.disconnected_timeout {
			a.set_state(.disconnected)
			return
		}
		if a.pairs[a.selected].nominated {
			a.set_state(.completed)
		} else {
			a.set_state(.connected)
		}
		return
	}

	if a.pairs.len == 0 {
		return
	}
	mut any_live := false
	for pair in a.pairs {
		if pair.state != .failed {
			any_live = true
			break
		}
	}
	if !any_live {
		a.set_state(.failed)
		return
	}
	if a.state == .gathering || a.state == .new {
		a.set_state(.checking)
	}
}

// handle_packet dispatches one datagram.
//
// A WebRTC socket carries STUN, DTLS, RTP and RTCP on the same port. STUN is
// the agent's business; everything else is the application's, and is handed
// over untouched.
fn (mut a Agent) handle_packet(packet InboundPacket) {
	if !stun.is_message(packet.data) {
		a.deliver_application_data(packet)
		return
	}
	message := stun.Message.decode(packet.data) or {
		a.log.debug('discarded a malformed STUN message from ${packet.from}: ${err.msg()}')
		return
	}

	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	if a.closed {
		return
	}

	match message.typ.class {
		.request { a.handle_binding_request(message, packet) }
		.success_response, .error_response { a.handle_binding_response(message, packet) }
		.indication {}
	}
}