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