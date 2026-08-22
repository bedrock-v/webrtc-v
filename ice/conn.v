module ice

import time
import webrtc.transport

// The application-facing side of an agent: wait for connectivity, then send and
// receive datagrams over whichever pair ICE selected.

// connect blocks until a candidate pair is carrying traffic.
//
// It does not wait for nomination. Once a pair succeeds in both directions it
// can carry data, and holding the application back until the controlling agent
// has finished nominating would add a round trip to every connection for no
// gain.
pub fn (mut a Agent) connect(timeout time.Duration) ! {
	deadline := time.now().add(timeout)
	for time.now() < deadline {
		state := a.state()
		match state {
			.connected, .completed {
				return
			}
			.failed {
				return AgentError{
					reason: .checks_failed
					detail: 'every candidate pair failed'
				}
			}
			.closed {
				return AgentError{
					reason: .closed
					detail: 'agent was closed while connecting'
				}
			}
			else {}
		}
		time.sleep(10 * time.millisecond)
	}
	return AgentError{
		reason: .timed_out
		detail: 'no candidate pair connected within ${timeout.milliseconds()}ms'
	}
}

// send transmits a datagram over the selected pair.
//
// It fails rather than buffering when no pair is selected. Queueing would hide
// a connectivity failure behind a growing backlog and deliver a burst of stale
// data if the connection ever recovered.
pub fn (mut a Agent) send(data []u8) !int {
	a.mu.lock()
	if a.closed {
		a.mu.unlock()
		return AgentError{
			reason: .closed
			detail: 'agent is closed'
		}
	}
	if a.selected < 0 || a.selected >= a.pairs.len {
		a.mu.unlock()
		return AgentError{
			reason: .wrong_state
			detail: 'no candidate pair is selected'
		}
	}
	pair := a.pairs[a.selected]
	socket_index := a.socket_for[pair.local.address.str()] or {
		a.mu.unlock()
		return AgentError{
			reason: .wrong_state
			detail: 'the selected pair has no socket'
		}
	}
	mut socket := a.sockets[socket_index]
	a.mu.unlock()

	if socket.relay != unsafe { nil } {
		mut relay := socket.relay
		return relay.send_to(pair.remote.address, data) or {
			return AgentError{
				reason: .transport
				detail: 'relaying to ${pair.remote.address}: ${err.msg()}'
			}
		}
	}

	mut conn := socket.conn
	destination := transport.socket_addr_to_net(pair.remote.address) or {
		return AgentError{
			reason: .transport
			detail: err.msg()
		}
	}
	sent := conn.write_to(destination, data) or {
		return AgentError{
			reason: .transport
			detail: 'send to ${pair.remote.address}: ${err.msg()}'
		}
	}
	return sent
}

// recv returns the next application datagram, waiting up to timeout.
//
// Only datagrams that arrived on the selected pair are returned; STUN is
// consumed by the agent and traffic from any other source is discarded.
pub fn (mut a Agent) recv(timeout time.Duration) ![]u8 {
	if a.is_closed() {
		return AgentError{
			reason: .closed
			detail: 'agent is closed'
		}
	}
	select {
		data := <-a.data {
			if data.len == 0 && a.is_closed() {
				// A receive on a closed channel succeeds with the zero value in
				// V 0.5.2, and an empty datagram is never a real one.
				return AgentError{
					reason: .closed
					detail: 'agent is closed'
				}
			}
			return data
		}
		timeout {
			return AgentError{
				reason: .timed_out
				detail: 'no data within ${timeout.milliseconds()}ms'
			}
		}
	}
	return AgentError{
		reason: .closed
		detail: 'agent is closed'
	}
}

// try_recv returns a datagram if one is already queued.
pub fn (mut a Agent) try_recv() ?[]u8 {
	select {
		data := <-a.data {
			if data.len == 0 && a.is_closed() {
				// The zero value of a closed channel, not a datagram: see recv.
				return none
			}
			return data
		}
		else {
			return none
		}
	}
	return none
}

// close shuts the agent down: sockets are closed, threads wind down and any
// blocked reader is released. It is safe to call more than once.
pub fn (mut a Agent) close() {
	a.mu.lock()
	if a.closed {
		a.mu.unlock()
		return
	}
	a.closed = true
	a.set_state(.closed)
	mut sockets := a.sockets.clone()
	a.mu.unlock()

	for mut socket in sockets {
		if socket.closed {
			continue
		}
		socket.closed = true
		if socket.relay != unsafe { nil } {
			// Closing a relay releases the allocation, which frees the relay's
			// port and quota now rather than when the lifetime runs out.
			mut relay := socket.relay
			relay.close()
			continue
		}
		socket.conn.close() or {}
	}

	// Closing the channels releases anything blocked on them. The reader
	// threads notice through is_closed on their next timeout.
	a.inbound.close()
	a.data.close()

	for handle in a.threads {
		handle.wait()
	}
	a.mu.lock()
	a.threads.clear()
	a.mu.unlock()
}

// statistics is a snapshot of what the agent is doing, for diagnostics.
pub struct Statistics {
pub:
	state             ConnectionState
	role              Role
	local_candidates  int
	remote_candidates int
	pairs             int
	succeeded_pairs   int
	failed_pairs      int
	pending_checks    int
	selected          ?CandidatePair
}

// statistics returns a snapshot of the agent's state.
pub fn (mut a Agent) statistics() Statistics {
	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	mut succeeded := 0
	mut failed := 0
	for pair in a.pairs {
		match pair.state {
			.succeeded { succeeded++ }
			.failed { failed++ }
			else {}
		}
	}
	selected := if a.selected >= 0 && a.selected < a.pairs.len {
		?CandidatePair(a.pairs[a.selected])
	} else {
		?CandidatePair(none)
	}
	return Statistics{
		state:             a.state
		role:              a.role
		local_candidates:  a.locals.len
		remote_candidates: a.remotes.len
		pairs:             a.pairs.len
		succeeded_pairs:   succeeded
		failed_pairs:      failed
		pending_checks:    a.pending.len
		selected:          selected
	}
}
