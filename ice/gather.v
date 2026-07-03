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