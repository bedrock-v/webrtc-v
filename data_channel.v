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