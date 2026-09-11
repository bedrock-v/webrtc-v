module webrtc

import time
import webrtc.datachannel

// The public data channel handle.
//
// It wraps datachannel.Channel so that a channel can be handed back before the
// transports exist: an application creates one, then negotiates, and the handle
// becomes usable when SCTP comes up. Without the wrapper the application would
// have to re-fetch the channel after connecting, which the browser API does not
// make it do.

// DataChannelState mirrors RTCDataChannel.readyState.
pub enum DataChannelState {
	connecting
	open
	closing
	closed
}

pub fn (s DataChannelState) str() string {
	return match s {
		.connecting { 'connecting' }
		.open { 'open' }
		.closing { 'closing' }
		.closed { 'closed' }
	}
}

// DataChannelMessage is one message read from a channel.
pub struct DataChannelMessage {
pub:
	// is_string distinguishes text from binary. It travels in the SCTP payload
	// protocol identifier rather than in the bytes, which is how an empty string
	// stays distinguishable from empty binary data.
	is_string bool
	data      []u8
}

// text returns the message as a string.
pub fn (m DataChannelMessage) text() string {
	return m.data.bytestr()
}

// DataChannel is a channel on a peer connection.
pub struct DataChannel {
mut:
	connection &PeerConnection      = unsafe { nil }
	channel    &datachannel.Channel = unsafe { nil }
	closed     bool
	options    DataChannelOptions
pub:
	label string
}

// state returns the channel's ready state.
pub fn (mut d DataChannel) state() DataChannelState {
	if d.closed {
		return .closed
	}
	mut channel := d.channel
	if channel == unsafe { nil } {
		// Created before the transports came up; it is not open yet, which is
		// exactly what connecting means.
		return .connecting
	}
	return match channel.state() {
		.connecting { DataChannelState.connecting }
		.open { DataChannelState.open }
		.closing { DataChannelState.closing }
		.closed { DataChannelState.closed }
	}
}

// id returns the SCTP stream identifier once the channel is open.
pub fn (mut d DataChannel) id() ?u16 {
	mut channel := d.channel
	if channel == unsafe { nil } {
		return none
	}
	return channel.stream_identifier
}

// ordered reports whether the channel preserves message order.
pub fn (mut d DataChannel) ordered() bool {
	mut channel := d.channel
	if channel == unsafe { nil } {
		return d.options.ordered
	}
	return channel.ordered()
}

// reliable reports whether every message is guaranteed to arrive.
pub fn (mut d DataChannel) reliable() bool {
	mut channel := d.channel
	if channel == unsafe { nil } {
		return d.options.max_retransmits == none && d.options.max_packet_lifetime == none
	}
	return channel.reliable()
}

// negotiated reports whether the channel was declared by both applications
// rather than opened through DCEP.
//
// A peer that opens a channel this side expected to be negotiated, or the
// reverse, is not speaking the protocol the application thinks it is.
// This is worth being able to check rather than assume.
pub fn (mut d DataChannel) negotiated() bool {
	mut channel := d.channel
	if channel == unsafe { nil } {
		return d.options.negotiated
	}
	return channel.negotiated
}

// protocol is the subprotocol name the channel was opened with, empty when it
// carries none.
pub fn (mut d DataChannel) protocol() string {
	mut channel := d.channel
	if channel == unsafe { nil } {
		return d.options.protocol
	}
	return channel.protocol
}

// send_text sends a string message.
pub fn (mut d DataChannel) send_text(text string) ! {
	d.send(text.bytes(), true)!
}

// send_binary sends a binary message.
pub fn (mut d DataChannel) send_binary(data []u8) ! {
	d.send(data, false)!
}

// send delivers a message.
pub fn (mut d DataChannel) send(data []u8, is_string bool) ! {
	mut channel := d.channel
	if d.closed || channel == unsafe { nil } {
		return PeerError{
			reason: .wrong_state
			detail: 'the channel "${d.label}" is ${d.state()}'
		}
	}
	channel.send(data, is_string) or {
		return PeerError{
			reason: .transport
			detail: err.msg()
		}
	}
}

// recv returns the next message, waiting up to timeout.
pub fn (mut d DataChannel) recv(timeout time.Duration) !DataChannelMessage {
	mut channel := d.channel
	if channel == unsafe { nil } {
		// Wait for the transports rather than failing outright: a channel
		// created before negotiation is legitimately used this way.
		deadline := time.now().add(timeout)
		for time.now() < deadline {
			if d.closed {
				break
			}
			channel = d.channel
			if channel != unsafe { nil } {
				break
			}
			time.sleep(5 * time.millisecond)
		}
	}
	if d.closed || channel == unsafe { nil } {
		return PeerError{
			reason: .wrong_state
			detail: 'the channel "${d.label}" is not open'
		}
	}

	message := channel.recv(timeout) or {
		if err is datachannel.ChannelError && err.reason == .timed_out {
			return PeerError{
				reason: .timed_out
				detail: 'no message on "${d.label}" within ${timeout.milliseconds()}ms'
			}
		}
		return PeerError{
			reason: .transport
			detail: err.msg()
		}
	}
	return DataChannelMessage{
		is_string: message.is_string
		data:      message.data
	}
}

// try_recv returns a message if one is already queued.
pub fn (mut d DataChannel) try_recv() ?DataChannelMessage {
	mut channel := d.channel
	if d.closed || channel == unsafe { nil } {
		return none
	}
	message := channel.try_recv()?
	return DataChannelMessage{
		is_string: message.is_string
		data:      message.data
	}
}

// close shuts the channel down.
pub fn (mut d DataChannel) close() {
	if d.closed {
		return
	}
	d.closed = true
	mut channel := d.channel
	if channel != unsafe { nil } {
		channel.close()
	}
}

fn (mut d DataChannel) mark_closed() {
	d.closed = true
}

// open_channel opens a channel on the live transports.
fn (mut pc PeerConnection) open_channel(label string, options DataChannelOptions) !&DataChannel {
	mut channel := pc.start_channel(label, options)!
	mut wrapper := &DataChannel{
		connection: pc
		channel:    channel
		label:      label
		options:    options
	}
	pc.mu.lock()
	pc.open_channels << wrapper
	pc.mu.unlock()
	return wrapper
}

// bind_channel opens a channel for a handle the application already holds.
//
// A channel created before the transports existed was handed back unopened, so
// the handle has to become usable in place - the application kept a reference
// to it and would otherwise be left holding one that never opens.
fn (mut pc PeerConnection) bind_channel(mut handle DataChannel) ! {
	mut channel := pc.start_channel(handle.label, handle.options)!
	pc.mu.lock()
	handle.channel = channel
	pc.mu.unlock()
}

// start_channel does the manager work both paths need.
fn (mut pc PeerConnection) start_channel(label string, options DataChannelOptions) !&datachannel.Channel {
	pc.mu.lock()
	mut manager := pc.channels
	pc.mu.unlock()
	if manager == unsafe { nil } {
		return PeerError{
			reason: .wrong_state
			detail: 'the data transport is not up'
		}
	}

	return if options.negotiated {
		identifier := options.id or {
			return PeerError{
				reason: .wrong_state
				detail: 'a negotiated channel needs an id, which must match on both sides'
			}
		}

		manager.create_negotiated(identifier, label, options.to_channel_options()) or {
			return PeerError{
				reason: .transport
				detail: err.msg()
			}
		}
	} else {
		manager.create(label, options.to_channel_options(), 15 * time.second) or {
			return PeerError{
				reason: .transport
				detail: err.msg()
			}
		}
	}
}
