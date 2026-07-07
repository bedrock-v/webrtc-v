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

// deliver_application_data queues a non-STUN datagram for the application.
fn (mut a Agent) deliver_application_data(packet InboundPacket) {
	a.mu.lock()
	accepted := a.selected >= 0 && a.selected < a.pairs.len
		&& a.pairs[a.selected].remote.address.equal(packet.from)
	if accepted {
		a.pairs[a.selected].last_received = time.now()
		a.last_activity = time.now()
	}
	a.mu.unlock()

	if !accepted {
		// Data from anywhere other than the selected pair is either late
		// traffic from a path that lost, or an injection attempt. Neither is
		// something to hand to the application.
		a.log.debug('dropped ${packet.data.len} bytes from ${packet.from}, which is not the selected pair')
		return
	}
	select {
		a.data <- packet.data {}
		else {
			a.log.warn('application queue full, dropped ${packet.data.len} bytes')
		}
	}
}

// handle_binding_request answers a connectivity check from the peer. The caller
// must hold the mutex.
fn (mut a Agent) handle_binding_request(message stun.Message, packet InboundPacket) {
	// Authenticate before doing anything that changes state. An unauthenticated
	// request must not create a peer-reflexive candidate, must not advance a
	// pair and must not be answered with anything an attacker could use.
	key := stun.short_term_key(a.local_pwd) or { return }
	message.check_message_integrity(key) or {
		a.log.debug('check from ${packet.from} failed integrity: ${err.msg()}')
		return
	}
	if message.has(stun.attr_fingerprint) {
		message.check_fingerprint() or {
			a.log.debug('check from ${packet.from} has a bad FINGERPRINT')
			return
		}
	}
	username := message.username() or {
		a.send_error_response(message, packet, stun.code_bad_request, 'USERNAME is required')
		return
	}
	expected := '${a.local_ufrag}:${a.remote_ufrag}'
	if username != expected {
		a.log.debug('check from ${packet.from} carries username "${username}", expected "${expected}"')
		a.send_error_response(message, packet, stun.code_unauthenticated, '')
		return
	}

	if a.resolve_role_conflict(message, packet) {
		return
	}

	// The source address may be one the peer never signalled, because a NAT
	// rewrote it. RFC 8445 section 7.3.1.3 calls that a peer-reflexive
	// candidate; learning it is often the only way a symmetric NAT is
	// traversed at all.
	a.learn_peer_reflexive(packet)

	index := a.find_pair_for(packet)
	if index >= 0 {
		a.pairs[index].last_received = time.now()
		a.last_activity = time.now()
		// RFC 8445 section 7.3.1.4: a check arriving on a pair we have not
		// probed schedules one, so that the path is confirmed in both
		// directions rather than only the one it arrived on.
		if a.pairs[index].state == .frozen || a.pairs[index].state == .failed {
			a.pairs[index].state = .waiting
			a.pairs[index].binding_requests = 0
		}
		if message.has_use_candidate() && a.role == .controlled {
			// The controlling agent has chosen this pair. A controlled agent
			// does not get a say, but it must not act on a pair that has not
			// been proven to work.
			a.pairs[index].nominated = true
			if a.pairs[index].state == .succeeded {
				a.select_pair(index)
			}
		}
	}

	a.send_success_response(message, packet)
}

// resolve_role_conflict implements RFC 8445 section 7.3.1.1.
//
// Both agents can believe they are controlling, which would leave nobody to
// nominate, or both controlled, which would leave nobody either. The conflict is
// settled by comparing tiebreakers: the larger one keeps its role. Returning
// true means the request was answered with an error and must not be processed
// further.
fn (mut a Agent) resolve_role_conflict(message stun.Message, packet InboundPacket) bool {
	if remote_tiebreaker := message.ice_controlling() {
		if a.role != .controlling {
			return false
		}
		if a.tiebreaker >= remote_tiebreaker {
			// We keep the role and tell the peer to switch.
			a.send_error_response(message, packet, stun.code_role_conflict, '')
			return true
		}
		a.log.info('role conflict: switching to controlled')
		a.role = .controlled
		sort_pairs(mut a.pairs, false)
		return false
	}
	if remote_tiebreaker := message.ice_controlled() {
		if a.role != .controlled {
			return false
		}
		if a.tiebreaker >= remote_tiebreaker {
			a.send_error_response(message, packet, stun.code_role_conflict, '')
			return true
		}
		a.log.info('role conflict: switching to controlling')
		a.role = .controlling
		sort_pairs(mut a.pairs, true)
		return false
	}
	return false
}

// learn_peer_reflexive records a remote candidate for a source address the peer
// never signalled.
fn (mut a Agent) learn_peer_reflexive(packet InboundPacket) {
	for remote in a.remotes {
		if remote.address.equal(packet.from) {
			return
		}
	}
	if a.remotes.len >= max_remote_candidates {
		return
	}
	candidate := Candidate{
		foundation: compute_foundation(.peer_reflexive, packet.from.ip, '', .udp)
		component:  component_rtp
		transport:  .udp
		priority:   compute_priority(.peer_reflexive, default_local_preference(packet.from.ip),
			component_rtp)
		address:    packet.from
		typ:        .peer_reflexive
	}
	a.remotes << candidate
	a.form_pairs()
	a.log.debug('learned peer-reflexive candidate ${candidate}')
}

// find_pair_for returns the index of the pair a datagram belongs to.
fn (a &Agent) find_pair_for(packet InboundPacket) int {
	if packet.socket >= a.sockets.len {
		return -1
	}
	local := a.sockets[packet.socket].base
	for i, pair in a.pairs {
		if !pair.remote.address.equal(packet.from) {
			continue
		}
		// A server-reflexive local candidate shares the socket of its base, so
		// match on either.
		if pair.local.address.equal(local) {
			return i
		}
		if related := pair.local.related {
			if related.equal(local) {
				return i
			}
		}
	}
	return -1
}

// handle_binding_response matches a response to the check that provoked it.
fn (mut a Agent) handle_binding_response(message stun.Message, packet InboundPacket) {
	key := message.transaction_id[..].hex()
	check := a.pending[key] or {
		// An unmatched transaction id is either a very late response or a
		// forgery. Either way there is nothing to do with it.
		a.log.debug('discarded a response with an unknown transaction id from ${packet.from}')
		return
	}
	a.pending.delete(key)

	if check.pair_index >= a.pairs.len {
		return
	}

	integrity_key := stun.short_term_key(a.remote_pwd) or { return }
	message.check_message_integrity(integrity_key) or {
		a.log.debug('response from ${packet.from} failed integrity: ${err.msg()}')
		return
	}

	if message.typ.class == .error_response {
		code := message.error_code() or {
			a.pairs[check.pair_index].state = .failed
			return
		}
		if code.code == stun.code_role_conflict {
			// The peer refused our role. Switch, and retry the pair with the
			// role it insisted on.
			a.role = if a.role == .controlling { Role.controlled } else { Role.controlling }
			a.log.info('peer reported a role conflict: switching to ${a.role}')
			sort_pairs(mut a.pairs, a.role == .controlling)
			a.pairs[check.pair_index].state = .waiting
			a.pairs[check.pair_index].binding_requests = 0
			return
		}
		a.log.debug('check to ${packet.from} was refused: ${code}')
		a.pairs[check.pair_index].state = .failed
		return
	}

	// A response must come from the address the check was sent to. Accepting
	// one from elsewhere would let an attacker who can see the transaction id
	// confirm a path that does not exist.
	if !a.pairs[check.pair_index].remote.address.equal(packet.from) {
		a.log.debug('response for ${a.pairs[check.pair_index].remote.address} arrived from ${packet.from}')
		return
	}

	now := time.now()
	a.pairs[check.pair_index].state = .succeeded
	a.pairs[check.pair_index].last_received = now
	a.pairs[check.pair_index].round_trip_time = now - check.sent_at
	a.last_activity = now
	if check.nominating {
		a.pairs[check.pair_index].nominated = true
	}
	a.log.debug('pair succeeded in ${a.pairs[check.pair_index].round_trip_time.milliseconds()}ms: ${a.pairs[check.pair_index]}')

	a.unfreeze_by_foundation()
	a.consider_selection(check.pair_index)
}

// consider_selection promotes a newly succeeded pair if it is the best so far.
fn (mut a Agent) consider_selection(index int) {
	if a.selected == index {
		if a.pairs[index].nominated {
			a.set_state(.completed)
		}
		return
	}
	// A pair the controlling agent has nominated wins outright. The choice is
	// not ours to second-guess: the two agents must agree on where traffic
	// goes, and priority is only the tiebreak used until one of them decides.
	// Comparing priorities here instead would leave a controlled agent sitting
	// on a pair the peer has stopped using.
	if !a.pairs[index].nominated && a.selected >= 0 && a.selected < a.pairs.len {
		current := a.pairs[a.selected]
		// A nominated pair is final: RFC 8445 section 8.1.1 stops checking once
		// one is agreed, and switching away from it would desynchronise the two
		// agents' idea of where traffic is going.
		if current.nominated {
			return
		}
		if current.priority(a.role == .controlling) >= a.pairs[index].priority(a.role == .controlling) {
			return
		}
	}
	a.select_pair(index)

	// The controlling agent nominates by repeating the check with
	// USE-CANDIDATE, which is what tells the peer the choice is final.
	if a.role == .controlling && !a.pairs[index].nominated {
		a.send_check(index, true)
		a.pairs[index].state = .succeeded
	}
}

// select_pair makes a pair the one carrying traffic.
fn (mut a Agent) select_pair(index int) {
	a.selected = index
	a.pairs[index].last_received = time.now()
	a.log.info('selected pair ${a.pairs[index]}')
	a.evaluate_state()
}

// send_success_response answers a check with the address it arrived from.
fn (mut a Agent) send_success_response(request stun.Message, packet InboundPacket) {
	mut response := stun.Message.response(request, .success_response)
	response.add_xor_mapped_address(packet.from) or { return }
	key := stun.short_term_key(a.local_pwd) or { return }
	raw := response.encode(integrity_key: key, fingerprint: true) or { return }
	a.send_raw(packet.socket, packet.from, raw)
}

// send_error_response answers a check with an error.
fn (mut a Agent) send_error_response(request stun.Message, packet InboundPacket, code int, reason string) {
	mut response := stun.Message.response(request, .error_response)
	response.add_error_code(code, reason) or { return }
	// A 401 is sent when the credentials did not match, so it cannot itself be
	// authenticated with them.
	raw := if code == stun.code_unauthenticated {
		response.encode(fingerprint: true) or { return }
	} else {
		key := stun.short_term_key(a.local_pwd) or { return }
		response.encode(integrity_key: key, fingerprint: true) or { return }
	}
	a.send_raw(packet.socket, packet.from, raw)
}