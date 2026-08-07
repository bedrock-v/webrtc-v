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

fn channel_type_from_value(v u8) ?ChannelType {
	return match v {
		0x00 { ChannelType.reliable }
		0x01 { ChannelType.partial_reliable_rexmit }
		0x02 { ChannelType.partial_reliable_timed }
		0x80 { ChannelType.reliable_unordered }
		0x81 { ChannelType.partial_reliable_rexmit_unordered }
		0x82 { ChannelType.partial_reliable_timed_unordered }
		else { none }
	}
}

// DcepError is returned when a DCEP message cannot be built or parsed.
pub struct DcepError {
pub:
	detail string
}

pub fn (e DcepError) msg() string {
	return 'datachannel: ${e.detail}'
}

pub fn (e DcepError) code() int {
	return 1
}

// Open is a DATA_CHANNEL_OPEN message.
pub struct Open {
pub:
	channel_type ChannelType = .reliable
	// priority is advisory. Nothing in this implementation acts on it, and
	// browsers largely ignore it too, but it round-trips so a peer that does
	// use it sees what was asked for.
	priority u16
	// reliability_parameter is the retransmission count or the lifetime in
	// milliseconds, depending on the channel type. It is zero for a reliable
	// channel.
	reliability_parameter u32
	label                 string
	// protocol is a subprotocol name, in the sense the WebSocket API uses.
	protocol string
}

// marshal serialises an OPEN message.
pub fn (o Open) marshal() ![]u8 {
	label := o.label.bytes()
	protocol := o.protocol.bytes()
	if label.len > max_label_bytes {
		return DcepError{
			detail: 'label of ${label.len} bytes exceeds the ${max_label_bytes}-byte limit'
		}
	}
	if protocol.len > max_protocol_bytes {
		return DcepError{
			detail: 'protocol of ${protocol.len} bytes exceeds the ${max_protocol_bytes}-byte limit'
		}
	}

	mut w := codec.Writer.with_capacity(12 + label.len + protocol.len)
	w.u8(message_type_open)
	w.u8(u8(o.channel_type))
	w.u16(o.priority)
	w.u32(o.reliability_parameter)
	w.u16(u16(label.len))
	w.u16(u16(protocol.len))
	w.bytes(label)
	w.bytes(protocol)
	return w.buf
}

// Open.decode parses an OPEN message.
pub fn Open.decode(data []u8) !Open {
	mut r := codec.Reader.new(data)
	typ := r.u8('message type') or { return short() }
	if typ != message_type_open {
		return DcepError{
			detail: 'message type 0x${typ.hex()} is not DATA_CHANNEL_OPEN'
		}
	}
	raw_channel_type := r.u8('channel type') or { return short() }
	channel_type := channel_type_from_value(raw_channel_type) or {
		return DcepError{
			detail: 'unknown channel type 0x${raw_channel_type.hex()}'
		}
	}
	priority := r.u16('priority') or { return short() }
	reliability := r.u32('reliability parameter') or { return short() }
	label_length := int(r.u16('label length') or { return short() })
	protocol_length := int(r.u16('protocol length') or { return short() })

	if label_length > max_label_bytes || protocol_length > max_protocol_bytes {
		return DcepError{
			detail: 'OPEN declares a label of ${label_length} and a protocol of ${protocol_length} bytes, over the limits'
		}
	}
	label := r.bytes(label_length, 'label') or {
		return DcepError{
			detail: 'OPEN declares a ${label_length}-byte label but only ${r.remaining()} bytes remain'
		}
	}
	protocol := r.bytes(protocol_length, 'protocol') or {
		return DcepError{
			detail: 'OPEN declares a ${protocol_length}-byte protocol but only ${r.remaining()} bytes remain'
		}
	}

	return Open{
		channel_type:          channel_type
		priority:              priority
		reliability_parameter: reliability
		label:                 label.bytestr()
		protocol:              protocol.bytestr()
	}
}