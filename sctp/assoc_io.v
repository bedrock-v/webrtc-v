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

// handle_datagram decodes a packet and dispatches its chunks.
fn (mut a Association) handle_datagram(datagram []u8) {
	packet := Packet.decode(datagram, default_max_chunks) or {
		a.log.debug('discarded a packet: ${err.msg()}')
		return
	}

	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	if a.closed {
		return
	}

	// The verification tag is what binds a packet to this association. An INIT
	// carries zero because the peer has not learned our tag yet, and an ABORT
	// may echo either tag; everything else must match, and a packet that does
	// not is discarded without any state change.
	if packet.chunks.len > 0 {
		first := packet.chunks[0].chunk_type() or { ChunkType.data }
		is_init := first == .init
		if !is_init && packet.verification_tag != a.my_verification_tag {
			a.log.debug('discarded a packet with verification tag 0x${packet.verification_tag.hex()}')
			return
		}
	}

	for chunk in packet.chunks {
		a.handle_chunk(chunk) or {
			a.log.debug('${chunk.name()}: ${err.msg()}')
			return
		}
		if a.state == .aborted || a.closed {
			return
		}
	}
}