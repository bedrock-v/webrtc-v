module ice

import net
import time
import webrtc.netaddr
import webrtc.stun
import webrtc.transport

// gather_timeout bounds one server-reflexive lookup. Gathering blocks the
// caller, so a STUN server that is down must not hold up the whole session; the
// host candidates are already usable by then.
const gather_timeout = time.Duration(2 * time.second)

// gather collects local candidates and starts the agent.
//
// Host candidates come from the local interfaces; each gets its own socket, so
// that the address a peer sees is the address we told it about. Server-reflexive
// candidates are then discovered by sending a Binding request out of each of
// those same sockets: a NAT mapping belongs to the source port that created it,
// so a reflexive address discovered on one socket is worthless on another.
//
// It is safe to call more than once; later calls do nothing.
pub fn (mut a Agent) gather() ! {
	a.mu.lock()
	if a.closed {
		a.mu.unlock()
		return AgentError{
			reason: .closed
			detail: 'agent is closed'
		}
	}
	if a.gathering_done {
		a.mu.unlock()
		return
	}
	a.gathering_done = true
	a.set_state(.gathering)
	interfaces := a.config.interfaces
	stun_servers := a.config.stun_servers.clone()
	policy := a.config.gather_policy
	a.mu.unlock()

	a.mu.lock()
	turn_servers := a.config.turn_servers.clone()
	a.mu.unlock()
	if policy == .relay_only && turn_servers.len == 0 {
		// Saying so is the point. Gathering host candidates anyway would leak
		// exactly the addresses this policy exists to hide, and gathering
		// nothing silently would look like a network fault.
		a.mu.lock()
		a.set_state(.failed)
		a.mu.unlock()
		return AgentError{
			reason: .no_candidates
			detail: 'the relay-only policy needs at least one TURN server'
		}
	}

	addresses := local_interface_addresses(interfaces)!
	if addresses.len == 0 {
		a.mu.lock()
		a.set_state(.failed)
		a.mu.unlock()
		return AgentError{
			reason: .no_candidates
			detail: 'no usable local interface addresses'
		}
	}

	// A socket is bound for every address whatever the policy: the policy
	// controls what is disclosed to the peer, not what this end can send from.
	// Without a socket there would be nothing for a server-reflexive candidate
	// to be reflexive of, and nothing to reach the relay over.
	for address in addresses {
		a.add_host_candidate(address, policy == .all) or {
			// One unusable interface must not abort gathering: a machine with a
			// half-configured adapter should still connect over the others.
			a.log.warn('skipping ${address}: ${err.msg()}')
			continue
		}
	}

	a.mu.lock()
	bound := a.sockets.len
	a.mu.unlock()
	if bound == 0 {
		a.mu.lock()
		a.set_state(.failed)
		a.mu.unlock()
		return AgentError{
			reason: .no_candidates
			detail: 'every local address failed to bind'
		}
	}

	if policy != .relay_only {
		for server in stun_servers {
			a.gather_reflexive(server) or {
				a.log.warn('server-reflexive gathering via ${server} failed: ${err.msg()}')
				continue
			}
		}
	}

	// Relays last: they are the slowest to set up and the least preferred, and
	// a connection often completes on a host pair before an allocation returns.
	if turn_servers.len > 0 {
		a.gather_relayed()
	}

	// Checked after the reflexive pass, because under the no-host policy that
	// pass is the only thing that can produce a candidate.
	a.mu.lock()
	gathered := a.locals.len
	a.mu.unlock()
	if gathered == 0 {
		a.mu.lock()
		a.set_state(.failed)
		a.mu.unlock()
		return AgentError{
			reason: .no_candidates
			detail: match policy {
				.no_host { 'the no-host policy gathered nothing; a reachable STUN or TURN server is required' }
				.relay_only { 'no relay would allocate an address' }
				.all { 'no candidates could be gathered' }
			}
		}
	}

	a.start()
	return
}

// add_host_candidate binds a socket to a local address and records the
// resulting host candidate.
fn (mut a Agent) add_host_candidate(address netaddr.IpAddr, announce bool) ! {
	// Binding to port 0 lets the kernel choose; the candidate cannot be
	// described until we read back which port it picked.
	bind_target := if address.family == .ipv6 {
		'[${address}]:0'
	} else {
		'${address}:0'
	}
	mut conn := net.listen_udp(bind_target) or {
		return AgentError{
			reason: .transport
			detail: 'binding ${bind_target}: ${err.msg()}'
		}
	}
	bound := transport.local_addr(conn) or {
		conn.close() or {}
		return AgentError{
			reason: .transport
			detail: 'reading the bound address of ${bind_target}: ${err.msg()}'
		}
	}
	// The kernel reports the address it bound, but for a socket bound to a
	// specific interface address that is the address we asked for; keep the
	// zone identifier, which the textual round trip drops.
	base := netaddr.SocketAddr.new(address, bound.port)

	candidate := Candidate{
		foundation: compute_foundation(.host, address, '', .udp)
		component:  component_rtp
		transport:  .udp
		priority:   compute_priority(.host, default_local_preference(address), component_rtp)
		address:    base
		typ:        .host
	}

	a.mu.lock()
	a.sockets << &LocalSocket{
		conn: conn
		base: base
	}
	index := a.sockets.len - 1
	a.socket_for[base.str()] = index
	a.mu.unlock()

	if announce {
		a.add_local_candidate(candidate)
	}
	return
}

// gather_reflexive asks a STUN server what address it sees each local socket
// coming from.
fn (mut a Agent) gather_reflexive(server string) ! {
	a.mu.lock()
	sockets := a.sockets.clone()
	a.mu.unlock()

	server_addr := netaddr.SocketAddr.parse(server) or {
		return AgentError{
			reason: .transport
			detail: 'bad STUN server address "${server}": ${err.msg()}'
		}
	}
	destination := transport.socket_addr_to_net(server_addr) or {
		return AgentError{
			reason: .transport
			detail: 'bad STUN server address "${server}": ${err.msg()}'
		}
	}

	for index, socket in sockets {
		if socket.base.family() != server_addr.family() {
			// A request to an IPv4 server out of an IPv6 socket cannot be
			// routed, and the reverse is equally hopeless.
			continue
		}
		mapped := a.reflexive_lookup(socket, destination) or {
			a.log.debug('no reflexive address for ${socket.base} via ${server}: ${err.msg()}')
			continue
		}
		if mapped.equal(socket.base) {
			// The server saw the same address we bound, so there is no NAT in
			// the way and the host candidate already covers this path.
			a.log.debug('${socket.base} is not behind a NAT')
			continue
		}

		candidate := Candidate{
			foundation: compute_foundation(.server_reflexive, socket.base.ip, server, .udp)
			component:  component_rtp
			transport:  .udp
			priority:   compute_priority(.server_reflexive, default_local_preference(mapped.ip),
				component_rtp)
			address:    mapped
			typ:        .server_reflexive
			related:    socket.base
		}

		a.mu.lock()
		a.socket_for[mapped.str()] = index
		a.mu.unlock()
		a.add_local_candidate(candidate)
	}
	return
}

// reflexive_lookup performs one Binding transaction on an existing socket.
//
// This is deliberately not the stunclient package: that one owns its socket,
// and the whole point here is to reuse the socket a host candidate is bound to.
fn (mut a Agent) reflexive_lookup(socket &LocalSocket, destination net.Addr) !netaddr.SocketAddr {
	mut request := stun.Message.new(.request, .binding)!
	raw := request.encode(fingerprint: true)!

	mut conn := socket.conn
	deadline := time.now().add(gather_timeout)
	mut attempt := 0
	for time.now() < deadline {
		attempt++
		conn.write_to(destination, raw) or {
			return AgentError{
				reason: .transport
				detail: 'sending a Binding request: ${err.msg()}'
			}
		}

		// Retransmit on a doubling schedule, bounded by the overall deadline.
		wait := 100 * time.millisecond * i64(1 << (attempt - 1))
		attempt_deadline := time.now().add(wait)
		for time.now() < attempt_deadline && time.now() < deadline {
			remaining := attempt_deadline - time.now()
			conn.set_read_timeout(remaining)
			mut buf := []u8{len: max_datagram}
			n, _ := conn.read(mut buf) or { break }

			response := stun.Message.decode(buf[..n]) or { continue }
			if response.transaction_id != request.transaction_id {
				continue
			}
			if response.typ.class != .success_response {
				return AgentError{
					reason: .transport
					detail: 'STUN server answered with ${response.typ.class}'
				}
			}
			return response.reflexive_address()!
		}
	}
	return AgentError{
		reason: .timed_out
		detail: 'no Binding response within ${gather_timeout.milliseconds()}ms'
	}
}

// add_local_candidate records a candidate, pairs it and notifies the
// application.
fn (mut a Agent) add_local_candidate(candidate Candidate) {
	a.mu.lock()
	for existing in a.locals {
		if existing.equal(candidate) {
			a.mu.unlock()
			return
		}
	}
	a.locals << candidate
	a.form_pairs()
	a.mu.unlock()

	a.log.debug('gathered local candidate ${candidate}')
	if callback := a.config.on_candidate {
		callback(candidate)
	}
}

// add_remote_candidate records a candidate signalled by the peer.
//
// This is the trickle ICE entry point: candidates arrive over time, and each
// one extends the check list rather than restarting it.
pub fn (mut a Agent) add_remote_candidate(candidate Candidate) ! {
	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	if a.closed {
		return AgentError{
			reason: .closed
			detail: 'agent is closed'
		}
	}
	if candidate.needs_resolution() {
		// The candidate names a host rather than an address. Resolving is a
		// query with a timeout, so it happens on its own thread and the
		// candidate is added when - and only if - the name resolves.
		a.threads << spawn a.resolve_and_add(candidate)
		return
	}
	if a.remotes.len >= max_remote_candidates {
		return AgentError{
			reason: .wrong_state
			detail: 'more than ${max_remote_candidates} remote candidates'
		}
	}
	for existing in a.remotes {
		if existing.equal(candidate) {
			return
		}
	}
	a.remotes << candidate
	a.form_pairs()
	a.log.debug('added remote candidate ${candidate}')
	if a.has_relays() {
		// A relay drops traffic from a peer it has no permission for, so the
		// permission has to exist before the first check goes out.
		a.threads << spawn a.permit_on_relays(candidate.address)
	}
	return
}

// add_remote_candidate_string parses and adds a candidate from its SDP form.
pub fn (mut a Agent) add_remote_candidate_string(line string) ! {
	a.add_remote_candidate(parse_candidate(line)!)!
}

// form_pairs rebuilds the check list from the current candidate sets. The
// caller must hold the mutex.
//
// Existing pairs keep their state, so a candidate arriving mid-session neither
// restarts checks that are already in flight nor discards one that has already
// succeeded.
fn (mut a Agent) form_pairs() {
	if a.remote_ufrag == '' || a.remote_pwd == '' {
		// Without the peer's credentials a check cannot be authenticated, so
		// there is nothing to schedule yet.
		return
	}

	for local in a.locals {
		for remote in a.remotes {
			if !pairable(local, remote) {
				continue
			}
			if a.find_pair(local.address, remote.address) >= 0 {
				continue
			}
			a.pairs << CandidatePair{
				local:  local
				remote: remote
				state:  .waiting
			}
		}
	}
	a.unfreeze_by_foundation()
	sort_pairs(mut a.pairs, a.role == .controlling)
}

// unfreeze_by_foundation moves one pair per foundation to waiting.
//
// RFC 8445 section 6.1.2.6 freezes redundant pairs so that a foundation is
// probed once rather than once per pair sharing it. Since checks are the only
// thing ICE puts on the wire, that is the difference between a handful of
// probes and a burst that looks like a scan.
fn (mut a Agent) unfreeze_by_foundation() {
	mut active := map[string]bool{}
	for pair in a.pairs {
		if pair.state == .waiting || pair.state == .in_progress || pair.state == .succeeded {
			active[pair.foundation()] = true
		}
	}
	for i in 0 .. a.pairs.len {
		if a.pairs[i].state != .frozen {
			continue
		}
		foundation := a.pairs[i].foundation()
		if foundation !in active {
			a.pairs[i].state = .waiting
			active[foundation] = true
		}
	}
}

// find_pair returns the index of the pair with the given addresses, or -1.
fn (a &Agent) find_pair(local netaddr.SocketAddr, remote netaddr.SocketAddr) int {
	for i, pair in a.pairs {
		if pair.local.address.equal(local) && pair.remote.address.equal(remote) {
			return i
		}
	}
	return -1
}
