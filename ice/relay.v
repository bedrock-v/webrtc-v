module ice

import webrtc.netaddr
import webrtc.turn

// Relayed candidates.
//
// A relayed candidate is an address on a TURN server that forwards to us. It is
// the last resort - it costs the relay's bandwidth and adds a hop - and it is
// the only thing that works when both peers are behind a NAT that will not let
// them reach each other directly.
//
// From the check list's point of view a relay is just another local socket:
// pairs are formed, checks are sent, nomination works the same. What differs is
// underneath, in `transmit` and `read_relay`, and in one rule that has no
// equivalent for a host candidate - a relay drops traffic from any peer it has
// no permission for, so every remote candidate has to be installed on every
// allocation before a check can reach it.

// gather_relayed allocates on each configured relay and records the result as a
// candidate.
fn (mut a Agent) gather_relayed() {
	a.mu.lock()
	servers := a.config.turn_servers.clone()
	logger := a.config.logger
	a.mu.unlock()

	for server in servers {
		address := server.url.replace('turns:', '').replace('turn:', '')
		mut client := turn.Client.new(address,
			username: server.username
			password: server.password
			logger:   logger
		) or {
			// One unusable relay must not stop the others, nor the host and
			// reflexive candidates that may well be enough on their own.
			a.log.warn('relay ${server.url} is unusable: ${err.msg()}')
			continue
		}

		relayed := client.allocate() or {
			a.log.warn('allocating on ${server.url} failed: ${err.msg()}')
			client.close()
			continue
		}

		a.mu.lock()
		a.sockets << &LocalSocket{
			base:  relayed
			relay: client
		}
		index := a.sockets.len - 1
		a.socket_for[relayed.str()] = index
		a.mu.unlock()

		candidate := Candidate{
			foundation: compute_foundation(.relayed, relayed.ip, address, .udp)
			component:  component_rtp
			transport:  .udp
			priority:   compute_priority(.relayed, default_local_preference(relayed.ip),
				component_rtp)
			address:    relayed
			// The base of a relayed candidate is the relayed address itself:
			// that is where traffic to us arrives, and there is no local socket
			// address a peer could use instead.
			related: client.mapped_address() or { netaddr.SocketAddr{} }
			typ:     .relayed
		}
		a.add_local_candidate(candidate)
		a.log.info('relayed candidate ${relayed} via ${server.url}')

		// Any remote candidate already known needs a permission before a check
		// can reach it.
		a.install_permissions(mut client)
	}
}

// install_permissions lets every known remote candidate through one relay.
fn (mut a Agent) install_permissions(mut client turn.Client) {
	a.mu.lock()
	remotes := a.remotes.clone()
	a.mu.unlock()

	for remote in remotes {
		client.create_permission(remote.address) or {
			a.log.warn('the relay refused a permission for ${remote.address}: ${err.msg()}')
			continue
		}
	}
}

// permit_on_relays installs a permission for one remote candidate on every
// allocation.
//
// It runs on its own thread because a permission is a transaction with the
// relay, and adding a candidate must not block for a round trip to it - a peer
// trickling ten candidates would otherwise stall the caller for ten round
// trips.
fn (mut a Agent) permit_on_relays(address netaddr.SocketAddr) {
	a.mu.lock()
	mut clients := []&turn.Client{}
	for socket in a.sockets {
		if socket.relay != unsafe { nil } {
			clients << socket.relay
		}
	}
	a.mu.unlock()
	if clients.len == 0 {
		return
	}

	for mut client in clients {
		client.create_permission(address) or {
			a.log.warn('the relay refused a permission for ${address}: ${err.msg()}')
			continue
		}
		// A channel makes the framing four bytes instead of thirty-six. It is
		// worth binding for a candidate that may end up carrying media, and
		// harmless for one that does not.
		client.bind_channel(address) or {
			a.log.debug('the relay refused a channel for ${address}: ${err.msg()}')
		}
	}
}

// has_relays reports whether any allocation exists. The caller must hold the
// mutex.
fn (a &Agent) has_relays() bool {
	for socket in a.sockets {
		if socket.relay != unsafe { nil } {
			return true
		}
	}
	return false
}
