module sctp

import time
import webrtc.internal.randutil

// Association establishment and teardown (RFC 4960 section 5).
//
// The four-way handshake exists because SCTP runs over an unauthenticated
// datagram transport in the general case: the server commits no memory until
// the client echoes a cookie proving it can receive at its claimed address.
// Over DTLS the peer is already authenticated, so the exchange is mostly
// ceremony here - but a peer that expects it will not proceed without it.

// connect establishes the association and blocks until it is usable.
pub fn (mut a Association) connect(timeout time.Duration) ! {
	a.mu.lock()
	if a.state != .closed {
		state := a.state
		a.mu.unlock()
		return AssociationError{
			reason: .wrong_state
			detail: 'the association is already ${state}'
		}
	}
	is_client := a.is_client
	a.mu.unlock()

	a.start()

	if is_client {
		a.send_init()!
	}

	deadline := time.now().add(timeout)
	for time.now() < deadline {
		state := a.state()
		match state {
			.established {
				return
			}
			.aborted {
				a.mu.lock()
				reason := a.abort_reason
				a.mu.unlock()
				return AssociationError{
					reason: .aborted
					detail: if reason != '' { reason } else { 'the association was aborted' }
				}
			}
			.closed {
				a.mu.lock()
				torn_down := a.torn_down
				reason := a.abort_reason
				a.mu.unlock()
				if torn_down {
					return AssociationError{
						reason: .closed
						detail: if reason != '' {
							reason
						} else {
							'the association closed while connecting'
						}
					}
				}
			}
			else {}
		}
		time.sleep(5 * time.millisecond)
	}
	return AssociationError{
		reason: .timed_out
		detail: 'the association did not establish within ${timeout.milliseconds()}ms'
	}
}

// start launches the association loop.
fn (mut a Association) start() {
	a.mu.lock()
	if a.closed || a.threads.len > 0 {
		a.mu.unlock()
		return
	}
	a.mu.unlock()
	a.threads << spawn a.run()
}

// send_init sends the first chunk of the handshake.
fn (mut a Association) send_init() ! {
	a.mu.lock()
	init := Init{
		initiate_tag:               a.my_verification_tag
		advertised_receiver_window: a.my_receive_window
		outbound_streams:           a.config.streams
		inbound_streams:            a.config.streams
		initial_tsn:                a.my_next_tsn
		// Advertising partial reliability up front is what lets a data channel
		// later use maxRetransmits; a peer that does not answer in kind simply
		// gets reliable delivery.
		parameters: a.negotiated_parameters()
	}
	a.set_state(.cookie_wait)
	a.mu.unlock()

	// An INIT is sent with a zero verification tag: the peer has not told us
	// its tag yet, and this is the packet that asks for it.
	a.send_chunks(0, [
		RawChunk{
			typ:   u8(ChunkType.init)
			value: init.marshal()!
		},
	])!
}

// handle_init answers a peer's INIT. The caller must hold the mutex.
fn (mut a Association) handle_init(init Init) ! {
	// A cookie the peer must echo back. RFC 4960 makes this a self-contained
	// authenticated blob so a server can stay stateless under flood; here the
	// association already exists behind an authenticated DTLS connection with
	// exactly one peer, so a remembered random value gives the same guarantee
	// without the machinery.
	a.cookie = randutil.bytes(32)!

	a.peer_verification_tag = init.initiate_tag
	a.peer_receive_window = init.advertised_receiver_window
	a.peer_supports_forward_tsn = init.supports_forward_tsn()
	// Everything below the peer's initial TSN counts as already received, so
	// the first data chunk closes the gap rather than opening one.
	a.last_received_tsn = init.initial_tsn - 1

	ack := Init{
		initiate_tag:               a.my_verification_tag
		advertised_receiver_window: a.my_receive_window
		outbound_streams:           min_u16(a.config.streams, init.inbound_streams)
		inbound_streams:            min_u16(a.config.streams, init.outbound_streams)
		initial_tsn:                a.my_next_tsn
		parameters:                 a.negotiated_parameters_with_cookie()
	}

	a.queue_outbound(RawChunk{
		typ:   u8(ChunkType.init_ack)
		value: ack.marshal()!
	})
}