module datachannel

import sync
import time
import webrtc.logging
import webrtc.sctp

// The data channel layer over an SCTP association.
//
// A Manager owns the association and routes what arrives on it: DCEP messages
// change channel state, and everything else is application data for the channel
// whose stream it came in on. One background thread does the routing, which is
// the same arrangement the layers below use and for the same reason - the
// ordering rules live in one place.

// max_channels bounds how many channels one association may carry. Each one is
// state we hold on behalf of a peer that can open them unilaterally.
pub const max_channels = 512

// Message is what an application reads from a channel.
pub struct Message {
pub:
	// is_string distinguishes a text message from a binary one. It is carried
	// in the SCTP payload protocol identifier, not in the bytes, which is how
	// an empty string stays distinguishable from empty binary data.
	is_string bool
	data      []u8
}

// text returns the message as a string. It is only meaningful when is_string
// is set.
pub fn (m Message) text() string {
	return m.data.bytestr()
}

// ChannelState follows the RTCDataChannel readyState values.
pub enum ChannelState {
	// connecting: the OPEN has been sent and the ACK has not arrived.
	connecting
	open
	closing
	closed
}

pub fn (s ChannelState) str() string {
	return match s {
		.connecting { 'connecting' }
		.open { 'open' }
		.closing { 'closing' }
		.closed { 'closed' }
	}
}

// ChannelOptions configures a channel, mirroring RTCDataChannelInit.
@[params]
pub struct ChannelOptions {
pub:
	// ordered preserves message order. Turning it off lets a later message be
	// delivered while an earlier one is still being retransmitted, which is
	// what a latency-sensitive application wants.
	ordered bool = true
	// max_retransmits abandons a message after this many retransmissions.
	// Setting it makes the channel partially reliable.
	max_retransmits ?u16
	// max_packet_lifetime abandons a message after this long. It is the other
	// way to make a channel partially reliable, and the two are mutually
	// exclusive.
	max_packet_lifetime ?u16
	// protocol is an optional subprotocol name.
	protocol string
	priority u16
}

// channel_type derives the DCEP channel type from the options.
fn (o ChannelOptions) channel_type() !ChannelType {
	retransmits := o.max_retransmits
	lifetime := o.max_packet_lifetime
	if retransmits != none && lifetime != none {
		// RFC 8832 section 6.1: a channel is reliable, retransmit-limited or
		// time-limited, and the two limits cannot both apply.
		return DcepError{
			detail: 'max_retransmits and max_packet_lifetime cannot both be set'
		}
	}
	if retransmits != none {
		return if o.ordered {
			ChannelType.partial_reliable_rexmit
		} else {
			ChannelType.partial_reliable_rexmit_unordered
		}
	}
	if lifetime != none {
		return if o.ordered {
			ChannelType.partial_reliable_timed
		} else {
			ChannelType.partial_reliable_timed_unordered
		}
	}
	return if o.ordered { ChannelType.reliable } else { ChannelType.reliable_unordered }
}

fn (o ChannelOptions) reliability_parameter() u32 {
	if retransmits := o.max_retransmits {
		return u32(retransmits)
	}
	if lifetime := o.max_packet_lifetime {
		return u32(lifetime)
	}
	return 0
}

// ChannelError is returned when a channel cannot be created or used.
pub struct ChannelError {
pub:
	reason ChannelErrorReason
	detail string
}

pub enum ChannelErrorReason {
	closed
	wrong_state
	timed_out
	too_large
	// exhausted: no stream identifier is available.
	exhausted
	protocol
}

pub fn (e ChannelError) msg() string {
	return 'datachannel: ${e.reason}: ${e.detail}'
}

pub fn (e ChannelError) code() int {
	return int(e.reason) + 10
}

// Channel is one data channel.
pub struct Channel {
mut:
	manager &Manager    = unsafe { nil }
	mu      &sync.Mutex = sync.new_mutex()
	state   ChannelState
	// inbound carries messages to the application.
	inbound chan Message = chan Message{cap: 128}
pub:
	stream_identifier u16
	label             string
	protocol          string
	channel_type      ChannelType
	// negotiated marks a channel the application declared on both sides rather
	// than opening through DCEP.
	negotiated bool
}

// state returns the channel's ready state.
pub fn (mut c Channel) state() ChannelState {
	c.mu.lock()
	defer {
		c.mu.unlock()
	}
	return c.state
}

// ordered reports whether the channel preserves message order.
@[inline]
pub fn (c &Channel) ordered() bool {
	return c.channel_type.is_ordered()
}

// reliable reports whether every message is guaranteed to arrive.
@[inline]
pub fn (c &Channel) reliable() bool {
	return c.channel_type.is_reliable()
}

// Config configures a manager.
@[params]
pub struct Config {
pub:
	// is_dtls_client decides which stream identifiers this end may use.
	//
	// RFC 8832 section 6 gives the DTLS client the even identifiers and the
	// server the odd ones. Without that split both ends could pick the same
	// stream for different channels and neither would notice until the messages
	// interleaved.
	is_dtls_client bool           = true
	max_channels   int            = max_channels
	logger         logging.Logger = logging.nop()
}

// Manager routes data channels over one SCTP association.
pub struct Manager {
mut:
	association &sctp.Association
	config      Config
	log         logging.Logger
	mu          &sync.Mutex = sync.new_mutex()

	channels map[u16]&Channel
	// next_stream is the next identifier to try, stepping by two so it stays on
	// our side of the split.
	next_stream u16

	// incoming carries channels the peer opened.
	incoming chan &Channel = chan &Channel{cap: 32}

	closed  bool
	threads []thread
}

// Manager.new starts routing over an established association.
pub fn Manager.new(association &sctp.Association, config Config) &Manager {
	mut manager := &Manager{
		association: unsafe { association }
		config:      config
		log:         config.logger.with_scope('datachannel')
		next_stream: if config.is_dtls_client { u16(0) } else { u16(1) }
	}
	manager.threads << spawn manager.run()
	return manager
}

// create opens a channel and waits for the peer to acknowledge it.
pub fn (mut m Manager) create(label string, options ChannelOptions, timeout time.Duration) !&Channel {
	channel_type := options.channel_type()!

	m.mu.lock()
	if m.closed {
		m.mu.unlock()
		return ChannelError{
			reason: .closed
			detail: 'the manager is closed'
		}
	}
	if m.channels.len >= m.config.max_channels {
		m.mu.unlock()
		return ChannelError{
			reason: .exhausted
			detail: 'already carrying ${m.channels.len} channels'
		}
	}
	stream := m.allocate_stream() or {
		m.mu.unlock()
		return ChannelError{
			reason: .exhausted
			detail: 'no stream identifier is available'
		}
	}

	mut channel := &Channel{
		manager:           m
		state:             .connecting
		stream_identifier: stream
		label:             label
		protocol:          options.protocol
		channel_type:      channel_type
	}
	m.channels[stream] = channel
	m.mu.unlock()

	// The stream's delivery policy has to be in place before any data goes out
	// on it, or the first message would be sent reliably whatever the channel
	// was asked for.
	m.apply_reliability(stream, options)

	open := Open{
		channel_type:          channel_type
		priority:              options.priority
		reliability_parameter: options.reliability_parameter()
		label:                 label
		protocol:              options.protocol
	}
	// The OPEN always goes out ordered and reliable, whatever the channel will
	// be: it has to arrive, and it has to arrive before the data that follows.
	m.association.send(stream, sctp.ppid_dcep, open.marshal()!, true) or {
		m.forget(stream)
		return ChannelError{
			reason: .closed
			detail: 'sending the channel open: ${err.msg()}'
		}
	}

	deadline := time.now().add(timeout)
	for time.now() < deadline {
		match channel.state() {
			.open {
				m.log.debug('channel "${label}" open on stream ${stream}')
				return channel
			}
			.closed {
				return ChannelError{
					reason: .closed
					detail: 'the channel closed while opening'
				}
			}
			else {}
		}
		time.sleep(2 * time.millisecond)
	}
	m.forget(stream)
	return ChannelError{
		reason: .timed_out
		detail: 'the peer did not acknowledge the channel within ${timeout.milliseconds()}ms'
	}
}

// create_negotiated registers a channel both applications already agreed on,
// without any DCEP exchange.
//
// The stream identifier is the application's to choose and must match on both
// sides. This is RTCDataChannelInit's `negotiated: true`, and it exists so a
// channel can be used immediately without waiting a round trip.
pub fn (mut m Manager) create_negotiated(stream_identifier u16, label string, options ChannelOptions) !&Channel {
	channel_type := options.channel_type()!

	m.mu.lock()
	defer {
		m.mu.unlock()
	}
	if m.closed {
		return ChannelError{
			reason: .closed
			detail: 'the manager is closed'
		}
	}
	if stream_identifier in m.channels {
		return ChannelError{
			reason: .wrong_state
			detail: 'stream ${stream_identifier} already carries a channel'
		}
	}

	mut channel := &Channel{
		manager:           m
		state:             .open
		stream_identifier: stream_identifier
		label:             label
		protocol:          options.protocol
		channel_type:      channel_type
		negotiated:        true
	}
	m.channels[stream_identifier] = channel
	m.apply_reliability(stream_identifier, options)
	return channel
}

// accept returns the next channel the peer opened.
pub fn (mut m Manager) accept(timeout time.Duration) !&Channel {
	if m.is_closed() {
		return ChannelError{
			reason: .closed
			detail: 'the manager is closed'
		}
	}
	select {
		channel := <-m.incoming {
			if channel == unsafe { nil } {
				// A receive on a closed channel succeeds with the zero value in
				// V 0.5.2, so a nil here means the manager was closed while we
				// were waiting, not that a channel arrived.
				return ChannelError{
					reason: .closed
					detail: 'the manager was closed'
				}
			}
			return channel
		}
		timeout {
			return ChannelError{
				reason: .timed_out
				detail: 'no channel opened within ${timeout.milliseconds()}ms'
			}
		}
	}
	return ChannelError{
		reason: .closed
		detail: 'the manager is closed'
	}
}

// allocate_stream picks the next free identifier on our side of the split. The
// caller must hold the mutex.
fn (mut m Manager) allocate_stream() ?u16 {
	// Two is the step, because the parity is what keeps the two ends from
	// choosing the same stream.
	for _ in 0 .. 32768 {
		candidate := m.next_stream
		// Wrapping would collide with an identifier already in use, so the
		// space is treated as exhausted instead.
		if int(m.next_stream) + 2 > 65535 {
			m.next_stream = 65535
		} else {
			m.next_stream += 2
		}
		if candidate !in m.channels {
			return candidate
		}
	}
	return none
}

// apply_reliability tells the association how hard to try on this stream.
fn (mut m Manager) apply_reliability(stream u16, options ChannelOptions) {
	mut lifetime := ?time.Duration(none)
	if milliseconds := options.max_packet_lifetime {
		lifetime = time.Duration(i64(milliseconds) * time.millisecond)
	}
	m.association.set_stream_reliability(stream,
		max_retransmits:     options.max_retransmits
		max_packet_lifetime: lifetime
	)
}

// apply_negotiated_reliability does the same from a peer's OPEN, where the
// policy arrives as a channel type and one number whose meaning depends on it.
fn (mut m Manager) apply_negotiated_reliability(stream u16, channel_type ChannelType, parameter u32) {
	match channel_type {
		.partial_reliable_rexmit, .partial_reliable_rexmit_unordered {
			m.association.set_stream_reliability(stream, max_retransmits: u16(parameter))
		}
		.partial_reliable_timed, .partial_reliable_timed_unordered {
			m.association.set_stream_reliability(stream,
				max_packet_lifetime: time.Duration(i64(parameter) * time.millisecond)
			)
		}
		else {}
	}
}