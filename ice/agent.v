module ice

import net
import sync
import time
import webrtc.internal.randutil
import webrtc.logging
import webrtc.netaddr
import webrtc.turn

// Role decides which agent nominates a pair. RFC 8445 section 6.1.1 gives the
// controlling agent that job; the controlled agent follows.
pub enum Role {
	controlling
	controlled
}

pub fn (r Role) str() string {
	return match r {
		.controlling { 'controlling' }
		.controlled { 'controlled' }
	}
}

// ConnectionState is the agent's view of connectivity, following the states of
// the RTCIceTransport interface.
pub enum ConnectionState {
	// new: created, nothing gathered or checked yet.
	new
	// gathering: collecting local candidates.
	gathering
	// checking: probing candidate pairs.
	checking
	// connected: a pair works and traffic can flow. Checking may continue in
	// case a better pair is found.
	connected
	// completed: a pair has been nominated and checking has stopped.
	completed
	// disconnected: the selected pair has stopped responding. Recovery is still
	// possible, so this is not terminal.
	disconnected
	// failed: no pair works, or the disconnected state lasted too long.
	failed
	// closed: shut down by the application.
	closed
}

pub fn (s ConnectionState) str() string {
	return match s {
		.new { 'new' }
		.gathering { 'gathering' }
		.checking { 'checking' }
		.connected { 'connected' }
		.completed { 'completed' }
		.disconnected { 'disconnected' }
		.failed { 'failed' }
		.closed { 'closed' }
	}
}

// max_datagram is the largest datagram the agent will read. Anything longer is
// not a WebRTC packet, and reading into a fixed buffer keeps a hostile peer
// from choosing our allocation size.
const max_datagram = 2048