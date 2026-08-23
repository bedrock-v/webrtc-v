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
			// A user initiated abort is how a peer says it is leaving on
			// purpose, so it is not worth a warning.
			if causes.any(it.code == cause_user_initiated_abort) {
				a.log.debug(a.abort_reason)
			} else {
				a.log.warn(a.abort_reason)
			}
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

// tick runs the timers and sends whatever is due.
fn (mut a Association) tick() {
	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	if a.closed {
		return
	}

	a.expire_queued()
	a.expire_retransmissions()
	a.fill_congestion_window()
	a.maybe_shutdown()
	a.flush()
}

// maybe_shutdown sends the SHUTDOWN once everything queued has been
// acknowledged, which is what makes it graceful rather than abrupt.
fn (mut a Association) maybe_shutdown() {
	if a.state != .shutdown_pending {
		return
	}
	if a.pending.len > 0 || a.inflight.len > 0 {
		return
	}
	a.queue_outbound(RawChunk{
		typ:   u8(ChunkType.shutdown)
		value: [u8(a.last_received_tsn >> 24), u8(a.last_received_tsn >> 16),
			u8(a.last_received_tsn >> 8), u8(a.last_received_tsn)]
	})
	a.set_state(.shutdown_sent)
}

// flush sends the queued control chunks and any acknowledgement that is due.
// The caller must hold the mutex.
fn (mut a Association) flush() {
	if a.sack_pending && (a.immediate_sack || time.now() >= a.sack_due_at) {
		a.control_queue << a.build_sack()
		a.sack_pending = false
		a.immediate_sack = false
	}
	if a.control_queue.len == 0 {
		return
	}

	chunks := a.control_queue.clone()
	a.control_queue.clear()
	tag := a.peer_verification_tag
	limit := a.transport.max_write()

	// Chunks are packed into as few packets as will hold them, but never into a
	// packet larger than the transport will carry. Sending one oversized packet
	// works against a test pipe and fails against DTLS, which refuses a write
	// bigger than one record - so the limit is enforced here rather than
	// discovered in production.
	mut batch := []RawChunk{}
	mut size := packet_header_size
	for chunk in chunks {
		chunk_size := chunk.padded_len()
		if batch.len > 0 && size + chunk_size > limit {
			a.send_chunks_locked(tag, batch)
			batch = []RawChunk{}
			size = packet_header_size
		}
		batch << chunk
		size += chunk_size
	}
	if batch.len > 0 {
		a.send_chunks_locked(tag, batch)
	}
}

// send_chunks_locked sends a packet. The caller must hold the mutex; the write
// itself happens with it held, which is acceptable because the transport is a
// DTLS connection whose write is a single non-blocking datagram.
fn (mut a Association) send_chunks_locked(tag u32, chunks []RawChunk) {
	packet := Packet{
		verification_tag: tag
		chunks:           chunks
	}
	raw := packet.marshal() or {
		a.log.warn('could not marshal a packet: ${err.msg()}')
		return
	}
	a.transport.write(raw) or { a.log.debug('write failed: ${err.msg()}') }
}

// send_chunks sends a packet without holding the mutex, for the handshake paths
// that run before the loop owns the state.
fn (mut a Association) send_chunks(tag u32, chunks []RawChunk) ! {
	packet := Packet{
		verification_tag: tag
		chunks:           chunks
	}
	raw := packet.marshal()!
	a.transport.write(raw) or {
		return AssociationError{
			reason: .transport
			detail: 'write failed: ${err.msg()}'
		}
	}
}
