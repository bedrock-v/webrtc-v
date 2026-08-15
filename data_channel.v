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