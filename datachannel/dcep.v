// Package datachannel implements WebRTC data channels: the DCEP establishment
// protocol of RFC 8832 and the message framing of RFC 8831, on top of an SCTP
// association.
//
// A data channel is one SCTP stream pair plus an agreement about how it
// behaves. SCTP already provides ordered and unordered delivery and partial
// reliability; DCEP is the two-message exchange that says which of them this
// channel wants, and gives it a label.
module datachannel

import webrtc.internal.codec

// DCEP message types (RFC 8832 section 8.2.1).
pub const message_type_ack = u8(0x02)
pub const message_type_open = u8(0x03)

// max_label_bytes and max_protocol_bytes bound the two strings in an OPEN
// message. Both come from a peer, and both are length-prefixed with 16 bits, so
// without a ceiling one message could ask us to allocate 128 KiB of text.
pub const max_label_bytes = 8192
pub const max_protocol_bytes = 8192

// ChannelType is the reliability and ordering a channel asks for
// (RFC 8832 section 8.2.1).
//
// The unordered variants have the high bit set, which is why they are 0x80
// apart from their ordered counterparts rather than sequential.
pub enum ChannelType as u8 {
	// reliable: every message arrives, in order. The default, and what a
	// browser gives you when you pass no options.
	reliable = 0x00
	// partial_reliable_rexmit: a message is abandoned after a number of
	// retransmissions. This is `maxRetransmits`.
	partial_reliable_rexmit = 0x01
	// partial_reliable_timed: a message is abandoned after a time. This is
	// `maxPacketLifeTime`.
	partial_reliable_timed            = 0x02
	reliable_unordered                = 0x80
	partial_reliable_rexmit_unordered = 0x81
	partial_reliable_timed_unordered  = 0x82
}

pub fn (t ChannelType) str() string {
	return match t {
		.reliable { 'reliable' }
		.partial_reliable_rexmit { 'partial-reliable (retransmits)' }
		.partial_reliable_timed { 'partial-reliable (timed)' }
		.reliable_unordered { 'reliable unordered' }
		.partial_reliable_rexmit_unordered { 'partial-reliable unordered (retransmits)' }
		.partial_reliable_timed_unordered { 'partial-reliable unordered (timed)' }
	}
}

// is_ordered reports whether the channel preserves message order.
@[inline]
pub fn (t ChannelType) is_ordered() bool {
	return u8(t) & 0x80 == 0
}

// is_reliable reports whether every message is guaranteed to arrive.
@[inline]
pub fn (t ChannelType) is_reliable() bool {
	return u8(t) & 0x7F == 0
}