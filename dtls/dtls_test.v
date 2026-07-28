module dtls

import encoding.hex
import sync
import time
import webrtc.srtp

// PipeTransport is an in-memory datagram channel between two connections.
//
// It models the properties of UDP that the handshake has to cope with: message
// boundaries are preserved, and datagrams can be dropped or reordered on
// demand, which is how the retransmission logic gets exercised.
struct PipeTransport {
mut:
	inbound chan []u8      = chan []u8{cap: 64}
	peer    &PipeTransport = unsafe { nil }
	mu      &sync.Mutex    = sync.new_mutex()
	// drop_next causes the next n sends to be discarded.
	drop_next int
	sent      int
	closed    bool
}

fn new_pipe_pair() (&PipeTransport, &PipeTransport) {
	mut a := &PipeTransport{}
	mut b := &PipeTransport{}
	a.peer = b
	b.peer = a
	return a, b
}

fn (mut p PipeTransport) send(data []u8) !int {
	p.mu.lock()
	if p.closed {
		p.mu.unlock()
		return error('pipe closed')
	}
	p.sent++
	drop := p.drop_next > 0
	if drop {
		p.drop_next--
	}
	p.mu.unlock()

	if drop {
		// Report success: a dropped datagram is indistinguishable from a
		// delivered one to the sender, which is the whole reason DTLS needs a
		// retransmission timer.
		return data.len
	}
	mut peer := p.peer
	// The payload is copied into a variable first. V 0.5.2 sends a zero value
	// when the expression in a select-send is a call, so `peer.inbound <-
	// data.clone()` would silently deliver an empty datagram.
	copy := data.clone()
	select {
		peer.inbound <- copy {}
		else {
			return error('peer queue full')
		}
	}
	return data.len
}

fn (mut p PipeTransport) recv(timeout time.Duration) ![]u8 {
	select {
		data := <-p.inbound {
			return data
		}
		timeout {
			return error('timeout')
		}
	}
	return error('closed')
}

fn (mut p PipeTransport) close() {
	p.mu.lock()
	p.closed = true
	p.mu.unlock()
}

fn (mut p PipeTransport) drop(n int) {
	p.mu.lock()
	p.drop_next = n
	p.mu.unlock()
}

// -- PRF -------------------------------------------------------------------

fn test_prf_is_deterministic_and_label_separated() {
	secret := 'secret'.bytes()
	seed := 'seed'.bytes()

	first := prf(secret, 'label', seed, 48)
	assert first.len == 48
	assert prf(secret, 'label', seed, 48) == first

	// A different label must give unrelated output; that separation is what
	// keeps the record keys, the Finished data and the SRTP material from being
	// derivable from each other.
	assert prf(secret, 'other', seed, 48) != first
	assert prf('other'.bytes(), 'label', seed, 48) != first
	assert prf(secret, 'label', 'other'.bytes(), 48) != first
}