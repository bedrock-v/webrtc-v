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

// default_receive_window is what we advertise as buffer space. It is SCTP's
// flow control: a sender may not have more than this many unacknowledged bytes
// outstanding, so it is the knob that stops a fast sender from overrunning us.
pub const default_receive_window = u32(1024 * 1024)

// default_rto_initial is the starting retransmission timeout
// (RFC 4960 section 15).
pub const default_rto_initial = 3 * time.second

// default_rto_min and default_rto_max bound it.
pub const default_rto_min = 200 * time.millisecond
pub const default_rto_max = 60 * time.second

// default_max_retransmits is how many times a chunk is resent before the
// association is declared dead.
pub const default_max_retransmits = 10

// default_sack_delay is how long acknowledgement is held back to let it ride
// with outgoing data or cover several chunks (RFC 4960 section 6.2).
pub const default_sack_delay = 200 * time.millisecond

// max_datagram is the largest packet the association will read.
const max_datagram = 65536

// tick_interval is how often the association loop wakes to run its timers when
// nothing is arriving.
const tick_interval = 20 * time.millisecond

// Transport is the datagram channel an association runs over.
//
// A dtls.Conn satisfies it as written, which is the intended pairing: SCTP over
// DTLS is what RFC 8261 specifies and what a data channel is built on.
pub interface Transport {
mut:
	write(data []u8) !int
	read(timeout time.Duration) ![]u8
	max_write() int
}