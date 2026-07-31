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

// Config configures an association.
@[params]
pub struct Config {
pub:
	role Role = .client
	// streams is how many streams to offer in each direction.
	streams u16 = default_streams
	// receive_window is the buffer space advertised to the peer.
	receive_window u32 = default_receive_window
	// max_message_size bounds one reassembled message.
	max_message_size int           = default_max_message_size
	rto_initial      time.Duration = default_rto_initial
	rto_min          time.Duration = default_rto_min
	rto_max          time.Duration = default_rto_max
	max_retransmits  int           = default_max_retransmits
	sack_delay       time.Duration = default_sack_delay
	// partial_reliability advertises FORWARD_TSN support, which is what lets a
	// stream give up on a message. Turning it off makes every stream reliable
	// whatever policy is set on it, and is here mostly so the behaviour against
	// a peer that does not support it can be exercised.
	partial_reliability bool           = true
	handshake_timeout   time.Duration  = 10 * time.second
	logger              logging.Logger = logging.nop()
}

// AssociationError is returned when an association cannot be established or
// used.
pub struct AssociationError {
pub:
	reason AssociationErrorReason
	detail string
}

pub enum AssociationErrorReason {
	closed
	wrong_state
	timed_out
	// aborted: the peer sent an ABORT, or a protocol violation forced one.
	aborted
	// too_large: the message exceeds what one association will carry.
	too_large
	// no_stream: the stream identifier is outside what was negotiated.
	no_stream
	// transport: the underlying datagram channel failed.
	transport
	// protocol: the peer sent something the association cannot proceed from.
	protocol
}

pub fn (e AssociationError) msg() string {
	return 'sctp: ${e.reason}: ${e.detail}'
}

pub fn (e AssociationError) code() int {
	return int(e.reason) + 40
}

// InflightChunk is a DATA chunk that has been sent and not yet acknowledged.
struct InflightChunk {
mut:
	data Data
	// sent_at is when it last went out, which the retransmission timer and the
	// round-trip measurement both use.
	sent_at time.Time
	// retransmits counts how many times it has been resent. A chunk that has
	// been retransmitted is not used to measure the round trip, because there
	// is no way to tell which transmission the acknowledgement answers.
	retransmits int
	// max_retransmits and expires_at are the stream's partial reliability
	// policy, captured when the chunk was queued. They are held per chunk
	// rather than read from the stream, so that changing a stream's policy
	// cannot give one message's fragments two different deadlines.
	max_retransmits ?u16
	expires_at      ?time.Time
	// acked marks a chunk covered by a gap block but not yet by the cumulative
	// acknowledgement. It stays in flight until the cumulative point passes it,
	// because the peer is entitled to renege.
	acked bool
	// missing_reports counts how many acknowledgements have named a later TSN
	// while leaving this one out, which is what triggers a fast retransmit.
	missing_reports int
}

// Association is one SCTP association.
pub struct Association {
mut:
	transport Transport
	config    Config
	log       logging.Logger
	mu        &sync.Mutex = sync.new_mutex()

	is_client bool
	state     State = .closed

	// Local side of the association.
	my_verification_tag u32
	my_next_tsn         u32
	my_receive_window   u32

	// Peer side.
	peer_verification_tag u32
	peer_receive_window   u32
	// peer_cumulative_ack is the highest TSN the peer has acknowledged
	// cumulatively.
	peer_cumulative_ack u32
	// last_received_tsn is the highest TSN below which we have everything, and
	// is what our own SACK reports.
	last_received_tsn u32
	// out_of_order holds TSNs received above the cumulative point, so they can
	// be reported as gap blocks and delivered once the gap fills.
	out_of_order map[u32]Data
	// seen_duplicates are TSNs received again since the last acknowledgement.
	seen_duplicates []u32

	peer_supports_forward_tsn bool
	// reliability is the per-stream partial reliability policy; a stream with no
	// entry is fully reliable.
	reliability map[u16]Reliability
	// abandoned records chunks given up on but not yet acknowledged past, which
	// is what FORWARD_TSN is rebuilt from when it has to be resent.
	abandoned map[u32]AbandonedChunk
	// forward_point is the highest TSN this end has told the peer to skip to.
	forward_point u32
	// pending_deadlines holds, for queued fragments of a stream with a lifetime
	// policy, when that message stops being worth sending.
	pending_deadlines map[u32]time.Time

	// Streams.
	inbound  map[u16]InboundStream
	outbound map[u16]OutboundStream

	// Outbound queues.
	pending  []Data
	inflight map[u32]InflightChunk

	// Congestion control (RFC 4960 section 7).
	congestion_window    u32
	slow_start_threshold u32
	// bytes_acked accumulates during congestion avoidance, which increases the
	// window by one MTU per round trip rather than per acknowledgement.
	bytes_acked u32

	// Retransmission timing (RFC 4960 section 6.3).
	rto           time.Duration
	smoothed_rtt  time.Duration
	rtt_variation time.Duration
	has_rtt       bool

	// Acknowledgement scheduling.
	sack_due_at  time.Time
	sack_pending bool
	// immediate_sack forces the next tick to acknowledge without waiting for
	// the delay, which RFC 4960 requires after a gap or a duplicate.
	immediate_sack bool
	// data_since_sack counts chunks received since the last acknowledgement, so
	// that every second one is acknowledged without waiting for the timer.
	data_since_sack int

	// State cookie, held by the server between INIT_ACK and COOKIE_ECHO.
	cookie []u8

	// control_queue is what goes out in the next packet. Queueing rather than
	// sending immediately lets several answers - an acknowledgement, a
	// heartbeat reply, more data - ride in one datagram.
	control_queue []RawChunk
	// held holds messages the application has not collected. They count against
	// the advertised receive window, which is how the application's slowness
	// reaches the sender rather than being absorbed by an unbounded queue.
	held []Message

	closed bool
	// torn_down separates "not started yet" from "finished". Both are the
	// CLOSED state in RFC 4960's diagram, but connect has to tell them apart:
	// a server sits in CLOSED until the client's INIT arrives, and treating
	// that as a teardown would make it give up before it began.
	torn_down bool
	threads   []thread
	// delivered carries complete messages to the application.
	delivered chan Message = chan Message{cap: 256}
	// abort_reason records why the association died, so a later call can report
	// something better than "closed".
	abort_reason string
}

// Association.new creates an association over the given transport. No packet is
// sent until connect is called.
pub fn Association.new(transport Transport, config Config) !&Association {
	mut link := transport
	if config.streams == 0 {
		return AssociationError{
			reason: .wrong_state
			detail: 'an association needs at least one stream'
		}
	}
	if config.max_message_size <= 0 {
		return AssociationError{
			reason: .wrong_state
			detail: 'max_message_size must be positive'
		}
	}

	// The verification tag and the initial TSN are both random. The tag is what
	// stops an off-path attacker from injecting into the association, and a
	// predictable initial TSN would let one guess which sequence numbers a
	// receiver is waiting for.
	verification_tag := randutil.next_u32_nonzero()!
	initial_tsn := randutil.next_u32()!

	// One MTU of congestion window to start with, which is what RFC 4960
	// section 7.2.1 allows for a path whose MTU is not yet known.
	initial_window := u32(4 * link.max_write())

	return &Association{
		transport:           transport
		config:              config
		log:                 config.logger.with_scope('sctp')
		is_client:           config.role == .client
		my_verification_tag: verification_tag
		my_next_tsn:         initial_tsn
		my_receive_window:   config.receive_window
		// The acknowledgement point starts one below the first TSN we will
		// send. Leaving it at zero would be wrong for any initial TSN in the
		// upper half of the space: every acknowledgement the peer sent would
		// compare as older than the sentinel under wrapping arithmetic and be
		// discarded, the congestion window would never open, and any transfer
		// larger than the initial window would stall for good. The initial TSN
		// is random, so that is roughly every other connection.
		peer_cumulative_ack:  initial_tsn - 1
		forward_point:        initial_tsn - 1
		last_received_tsn:    0
		congestion_window:    initial_window
		slow_start_threshold: config.receive_window
		rto:                  config.rto_initial
	}
}

// state returns the association's current state.
pub fn (mut a Association) state() State {
	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	return a.state
}

// role returns which end of the handshake this association took.
@[inline]
pub fn (a &Association) role() Role {
	return if a.is_client { Role.client } else { Role.server }
}

// max_message_size is the largest message this association will send or accept.
@[inline]
pub fn (a &Association) max_message_size() int {
	return a.config.max_message_size
}

// is_closed reports whether the association has been shut down.
fn (mut a Association) is_closed() bool {
	a.mu.lock()
	defer {
		a.mu.unlock()
	}
	return a.closed
}

// set_state records a state transition. The caller must hold the mutex.
fn (mut a Association) set_state(state State) {
	if a.state == state {
		return
	}
	a.log.debug('state ${a.state} -> ${state}')
	a.state = state
}