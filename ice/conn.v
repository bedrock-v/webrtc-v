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