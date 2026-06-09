// Package stunclient performs STUN transactions over UDP.
//
// It is separate from the stun package because that one is a pure codec with no
// I/O: an application that only needs to parse or build STUN messages should not
// link a socket implementation. This package adds the socket, the timers and the
// retransmission schedule.
module stunclient

import net
import time
import webrtc.logging
import webrtc.netaddr
import webrtc.stun

// max_datagram is the largest datagram the client will read. STUN messages are
// far smaller; the ceiling exists so a hostile server cannot make the client
// allocate an arbitrary buffer.
const max_datagram = 1500

// ClientConfig tunes the retransmission behaviour described in RFC 8489
// section 6.2.1.
//
// The defaults follow the RFC: a 500 ms initial timeout doubling on each retry,
// seven transmissions in total. That is deliberately patient - it is meant for
// a standalone binding lookup. An ICE agent does not use this schedule; it
// paces its own checks and treats each one as a single transmission.
@[params]
pub struct ClientConfig {
pub:
	rto               time.Duration = 500 * time.millisecond
	max_transmissions int           = 7
	// software, when set, is advertised in a SOFTWARE attribute. It is empty by
	// default because naming the implementation and version to every server on
	// the path is a needless disclosure.
	software string
	logger   logging.Logger = logging.nop()
}