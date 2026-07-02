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

// max_remote_candidates bounds how many candidates a peer may signal. Each one
// multiplies the check list, so an unbounded list is a way to make an agent
// spend the rest of its life sending probes.
pub const max_remote_candidates = 64

// max_inbound_queue is how many datagrams may wait for the agent loop.
const max_inbound_queue = 256

// max_data_queue is how many application payloads may wait to be read.
//
// A bulk transfer does overflow this and lose datagrams, and the obvious fix -
// a deeper queue - measured slower: 1024 dropped loopback throughput from about
// 6.5 MB/s to 4.8 MB/s. The queue is a buffer in front of a congestion
// controller, so making it deeper mostly inflates the round-trip estimate that
// controller is working from. Losing the tail of a burst is the cheaper signal,
// and it is the one SCTP is designed to read.
const max_data_queue = 256

// AgentConfig configures an agent. Every field has a working default; a caller
// that sets nothing gets an agent that gathers host candidates and checks them.
// TurnServer is a relay to allocate on.
pub struct TurnServer {
pub:
	// url is "host:port", optionally prefixed with "turn:".
	url string
	// username and password are the long-term credentials. A relay without them
	// is an open relay and this client will not use one.
	username string
	password string
}

// GatherPolicy limits which kinds of candidate are gathered.
//
// It is a privacy control as much as a connectivity one: every candidate
// gathered is disclosed to the peer, and a host candidate discloses the
// machine's local addresses.
pub enum GatherPolicy {
	// all gathers host and server-reflexive candidates, and relayed ones once
	// TURN exists. This is the default and what connects most often.
	all
	// no_host omits host candidates, so a peer on the same network learns only
	// the address a STUN server saw. It costs local-network connectivity.
	no_host
	// relay_only gathers nothing but relayed candidates. TURN is not
	// implemented, so an agent configured this way currently gathers nothing and
	// says so rather than quietly falling back to a policy that leaks addresses.
	relay_only
}