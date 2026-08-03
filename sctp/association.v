module sctp

import sync
import time
import webrtc.internal.randutil
import webrtc.logging

// The SCTP association: its state, configuration and lifecycle.
//
// The concurrency model matches the ICE agent's, and for the same reason. One
// thread owns every piece of mutable state: it reads from the transport,
// processes chunks, runs the retransmission and acknowledgement timers, and
// sends. Public methods take a mutex to queue work or read a snapshot. SCTP has
// a great many ordering rules - what to acknowledge, when to retransmit, when a
// message becomes deliverable - and they are far easier to keep straight in one
// place.

// Role decides which end initiates. RFC 8841 makes the DTLS client the SCTP
// client, so a caller normally passes the DTLS role straight through.
pub enum Role {
	client
	server
}

pub fn (r Role) str() string {
	return match r {
		.client { 'client' }
		.server { 'server' }
	}
}

// State follows the association state diagram of RFC 4960 section 4.
pub enum State {
	closed
	cookie_wait
	cookie_echoed
	established
	shutdown_pending
	shutdown_sent
	shutdown_received
	shutdown_ack_sent
	aborted
}

pub fn (s State) str() string {
	return match s {
		.closed { 'closed' }
		.cookie_wait { 'cookie-wait' }
		.cookie_echoed { 'cookie-echoed' }
		.established { 'established' }
		.shutdown_pending { 'shutdown-pending' }
		.shutdown_sent { 'shutdown-sent' }
		.shutdown_received { 'shutdown-received' }
		.shutdown_ack_sent { 'shutdown-ack-sent' }
		.aborted { 'aborted' }
	}
}

// default_streams is how many streams each direction offers. WebRTC data
// channels take one stream each, so this is the channel ceiling.
pub const default_streams = u16(1024)