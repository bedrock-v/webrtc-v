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