module sctp

import time

// The association loop, and everything it drives: reading packets, dispatching
// chunks, sending queued data, retransmitting what went unacknowledged, and
// deciding when to acknowledge.

// outbound_queue is the chunks waiting to go out in the next packet. It lives
// on the association so that a handler can queue a reply without sending a
// packet of its own, which lets several answers ride in one datagram.
struct OutboundChunk {
	chunk RawChunk
}

// queue_outbound adds a control chunk to the next outgoing packet. The caller
// must hold the mutex.
fn (mut a Association) queue_outbound(chunk RawChunk) {
	a.control_queue << chunk
}

// run is the association loop.
fn (mut a Association) run() {
	for {
		if a.is_closed() {
			return
		}
		// A short read timeout is what lets the timers run when nothing is
		// arriving. The transport is expected to return an error on timeout
		// rather than block.
		datagram := a.transport.read(tick_interval) or {
			a.tick()
			continue
		}
		a.handle_datagram(datagram)
		a.tick()
	}
}