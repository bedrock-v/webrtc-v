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

// handle_chunk dispatches one chunk. The caller must hold the mutex.
fn (mut a Association) handle_chunk(chunk RawChunk) ! {
	typ := chunk.chunk_type() or {
		// An unknown chunk is handled by the rule its type number encodes,
		// which is what makes the protocol extensible.
		match unrecognised_chunk_action(chunk.typ) {
			.stop_processing, .stop_and_report {
				return AssociationError{
					reason: .protocol
					detail: 'unrecognised chunk type ${chunk.typ} requires the packet to be discarded'
				}
			}
			.skip, .skip_and_report {
				a.log.debug('skipping unrecognised chunk type ${chunk.typ}')
				return
			}
		}
		return
	}

	match typ {
		.init {
			a.handle_init(unmarshal_init(chunk.value)!)!
		}
		.init_ack {
			a.handle_init_ack(unmarshal_init(chunk.value)!)!
		}
		.cookie_echo {
			a.handle_cookie_echo(chunk.value)!
		}
		.cookie_ack {
			a.handle_cookie_ack()
		}
		.data {
			a.handle_data(unmarshal_data(chunk.flags, chunk.value)!)!
		}
		.sack {
			a.handle_sack(unmarshal_sack(chunk.value)!)
		}
		.forward_tsn {
			a.handle_forward_tsn(unmarshal_forward_tsn(chunk.value)!)
		}
		.heartbeat {
			// Echo the payload back unchanged; that is the whole protocol.
			a.queue_outbound(RawChunk{
				typ:   u8(ChunkType.heartbeat_ack)
				value: chunk.value
			})
		}
		.heartbeat_ack {}
		.abort {
			causes := unmarshal_error_causes(chunk.value) or { []ErrorCause{} }
			mut reasons := []string{cap: causes.len}
			for cause in causes {
				reasons << cause_name(cause.code)
			}
			a.abort_reason = if reasons.len > 0 {
				'the peer aborted: ${reasons.join(', ')}'
			} else {
				'the peer aborted'
			}
			a.log.warn(a.abort_reason)
			a.set_state(.aborted)
		}
		.shutdown {
			a.set_state(.shutdown_received)
			a.queue_outbound(RawChunk{
				typ: u8(ChunkType.shutdown_ack)
			})
			a.set_state(.shutdown_ack_sent)
		}
		.shutdown_ack {
			a.queue_outbound(RawChunk{
				typ: u8(ChunkType.shutdown_complete)
			})
			a.torn_down = true
			a.set_state(.closed)
		}
		.shutdown_complete {
			a.torn_down = true
			a.set_state(.closed)
		}
		.error {
			causes := unmarshal_error_causes(chunk.value) or { []ErrorCause{} }
			for cause in causes {
				a.log.warn('peer reported ${cause_name(cause.code)}')
			}
		}
		.ecne, .cwr, .reconfig {
			// Explicit congestion notification and stream reconfiguration are
			// not implemented. Ignoring them is safe: the association continues
			// with its own congestion control, and a channel closed through
			// RECONFIG is instead closed by the layer above.
			a.log.debug('ignoring a ${typ} chunk')
		}
	}
}