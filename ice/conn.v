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