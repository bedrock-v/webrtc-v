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

pub fn (p GatherPolicy) str() string {
	return match p {
		.all { 'all' }
		.no_host { 'no-host' }
		.relay_only { 'relay-only' }
	}
}

@[params]
pub struct AgentConfig {
pub:
	role Role = .controlling
	// stun_servers are "host:port" addresses used to discover server-reflexive
	// candidates.
	stun_servers []string
	// local_ufrag and local_pwd override the generated ICE credentials. Leave
	// them empty unless resuming a session: generated credentials come from the
	// system CSPRNG, and supplying weak ones lets an off-path attacker answer
	// connectivity checks.
	local_ufrag string
	local_pwd   string
	interfaces  InterfaceOptions
	// gather_policy limits which candidate types are gathered.
	gather_policy GatherPolicy = .all
	// turn_servers are relays to allocate an address on. A relayed candidate is
	// the last resort and the only one that works when both peers are behind a
	// NAT that will not hairpin.
	turn_servers []TurnServer
	// check_interval is Ta from RFC 8445 section 14.2: the pacing between
	// connectivity checks. Checks are what ICE spends bandwidth on, so this is
	// the knob that trades connection setup latency against burst size.
	check_interval time.Duration = 50 * time.millisecond
	// max_binding_requests is how many times one pair is probed before it is
	// declared failed.
	max_binding_requests int = 7
	// binding_timeout is how long to wait for a response before retransmitting.
	binding_timeout time.Duration = 500 * time.millisecond
	// keepalive_interval paces the consent checks of RFC 7675 on the selected
	// pair. Without them a NAT mapping expires silently and the connection dies
	// with no error anywhere.
	keepalive_interval time.Duration = 2 * time.second
	// disconnected_timeout is how long the selected pair may go without traffic
	// before the agent reports disconnected.
	disconnected_timeout time.Duration = 5 * time.second
	// failed_timeout is how long the agent stays disconnected before failing.
	failed_timeout time.Duration  = 25 * time.second
	logger         logging.Logger = logging.nop()
	// on_candidate is called for each local candidate as it is gathered, which
	// is what trickle ICE needs.
	on_candidate ?fn (Candidate)
	// on_state_change is called whenever the connection state changes.
	on_state_change ?fn (ConnectionState)
}

// localSocket is one bound UDP socket and the base address it represents.
struct LocalSocket {
mut:
	conn &net.UdpConn = unsafe { nil }
	base netaddr.SocketAddr
	// relay is set for a socket that reaches peers through a TURN allocation.
	// Sending then means asking the relay to forward, and receiving means
	// unwrapping what the relay forwarded back; the check list above does not
	// know the difference, which is the point.
	relay  &turn.Client = unsafe { nil }
	closed bool
}

// inboundPacket is a datagram handed from a socket reader to the agent loop.
struct InboundPacket {
	socket int
	from   netaddr.SocketAddr
	data   []u8
}

// pendingCheck records a connectivity check awaiting a response.
struct PendingCheck {
mut:
	pair_index int
	sent_at    time.Time
	nominating bool
}

// Agent runs ICE for one component of one transport.
//
// The design is a single-threaded state machine fed by channels. One thread per
// socket does nothing but read datagrams and forward them; one agent thread
// owns every piece of mutable state and is the only place checks are sent,
// responses are matched and the state machine advances. Public methods take a
// mutex to read or queue work. That leaves exactly one place where ICE's
// ordering rules have to hold, instead of spreading them across every thread
// that might receive a packet.
pub struct Agent {
mut:
	config AgentConfig
	mu     &sync.Mutex = sync.new_mutex()
	log    logging.Logger

	state      ConnectionState = .new
	role       Role
	tiebreaker u64

	local_ufrag  string
	local_pwd    string
	remote_ufrag string
	remote_pwd   string

	sockets []&LocalSocket
	// socket_for maps a local candidate's address to the socket that owns it.
	// A server-reflexive candidate shares the socket of the host candidate it
	// was discovered from, which is what makes the reflexive address usable.
	socket_for map[string]int
	locals     []Candidate
	remotes    []Candidate
	pairs      []CandidatePair
	pending    map[string]PendingCheck

	selected      int = -1
	last_activity time.Time

	gathering_done bool
	closed         bool

	inbound chan InboundPacket = chan InboundPacket{cap: max_inbound_queue}
	data    chan []u8          = chan []u8{cap: max_data_queue}
	threads []thread
}

// Agent.new creates an agent. No socket is opened until gather is called.
pub fn Agent.new(config AgentConfig) !&Agent {
	if config.max_binding_requests < 1 {
		return AgentError{
			reason: .bad_credentials
			detail: 'max_binding_requests must be at least 1'
		}
	}
	ufrag := if config.local_ufrag != '' {
		config.local_ufrag
	} else {
		randutil.ice_ufrag()!
	}
	pwd := if config.local_pwd != '' { config.local_pwd } else { randutil.ice_pwd()! }
	validate_credentials(ufrag, pwd)!

	return &Agent{
		config:        config
		log:           config.logger.with_scope('ice')
		role:          config.role
		tiebreaker:    randutil.next_u64()!
		local_ufrag:   ufrag
		local_pwd:     pwd
		last_activity: time.now()
	}
}

// validate_credentials enforces the length floors of RFC 8445 section 5.2.1.
//
// The password is the only secret protecting connectivity checks. Anything
// shorter than 22 characters of ice-char falls below the 128 bits the RFC
// requires and puts the session within reach of an off-path attacker who can
// guess it.
fn validate_credentials(ufrag string, pwd string) ! {
	if ufrag.len < 4 || ufrag.len > 256 {
		return AgentError{
			reason: .bad_credentials
			detail: 'ufrag must be 4 to 256 characters, got ${ufrag.len}'
		}
	}
	if pwd.len < 22 || pwd.len > 256 {
		return AgentError{
			reason: .bad_credentials
			detail: 'password must be 22 to 256 characters, got ${pwd.len}'
		}
	}
}

// local_credentials returns the ufrag and password to signal to the peer.
pub fn (mut a Agent) local_credentials() (string, string) {
	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	return a.local_ufrag, a.local_pwd
}

// set_remote_credentials records the peer's ICE credentials. Checks cannot
// start until they are known, because every check is authenticated with them.
pub fn (mut a Agent) set_remote_credentials(ufrag string, pwd string) ! {
	validate_credentials(ufrag, pwd)!
	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	if a.closed {
		return AgentError{
			reason: .closed
			detail: 'agent is closed'
		}
	}
	a.remote_ufrag = ufrag
	a.remote_pwd = pwd
	a.form_pairs()
	return
}

// state returns the current connection state.
pub fn (mut a Agent) state() ConnectionState {
	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	return a.state
}

// role returns the agent's ICE role, which may have changed since construction
// if a role conflict was resolved.
pub fn (mut a Agent) role() Role {
	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	return a.role
}

// local_candidates returns the candidates gathered so far.
pub fn (mut a Agent) local_candidates() []Candidate {
	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	return a.locals.clone()
}

// selected_pair returns the pair currently carrying traffic.
pub fn (mut a Agent) selected_pair() ?CandidatePair {
	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	if a.selected < 0 || a.selected >= a.pairs.len {
		return none
	}
	return a.pairs[a.selected]
}