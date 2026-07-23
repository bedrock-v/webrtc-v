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