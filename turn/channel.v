// Package turn is a TURN client (RFC 8656): it asks a relay for an address and
// forwards traffic through it.
//
// A relay is what connects two peers that cannot reach each other directly -
// symmetric NAT on both sides, or a network that blocks everything but the
// path to the relay. It costs the relay's bandwidth and adds a hop, so ICE
// tries it last; but when it is needed, nothing else works.
//
// This is the client half only. Running a relay is a different program with
// different concerns (quotas, abuse, accounting) and does not belong in a
// library that dials out.
module turn

import webrtc.internal.codec
import webrtc.netaddr

// Channel numbers and the ChannelData framing (RFC 8656 section 12).
//
// A Send indication carries the peer's address in every datagram, which costs
// 36 bytes of header on each one. A channel binds a peer address to a 16-bit
// number so the header is four bytes instead. For media that is the difference
// between a few percent of overhead and a tenth of it, which is why every
// implementation binds channels for the addresses it uses.

// channel_min and channel_max bound the numbers reserved for ChannelData. The
// range matters for demultiplexing: RFC 7983 relies on the first byte of a
// datagram, and 0x40-0x7F is what identifies TURN channel data.
pub const channel_min = u16(0x4000)
pub const channel_max = u16(0x7FFF)

// channel_header_size is the channel number and the length field.
pub const channel_header_size = 4

// is_channel_data reports whether a datagram is ChannelData rather than a STUN
// message.
@[inline]
pub fn is_channel_data(b []u8) bool {
	if b.len < channel_header_size {
		return false
	}
	return b[0] >= 0x40 && b[0] <= 0x7f
}

// ChannelData is one framed datagram to or from a bound peer.
pub struct ChannelData {
pub:
	channel u16
	payload []u8
}

// encode frames a payload for a channel.
//
// Over UDP the length field is redundant - the datagram boundary already says
// how long the payload is - but it is what lets the same framing run over TCP,
// and a server is entitled to check it.
pub fn (c ChannelData) encode() ![]u8 {
	if c.channel < channel_min || c.channel > channel_max {
		return TurnError{
			reason: .bad_message
			detail: 'channel ${c.channel} is outside the 0x4000-0x7FFF range'
		}
	}
	mut w := codec.Writer.with_capacity(channel_header_size + c.payload.len)
	w.u16(c.channel)
	w.u16(u16(c.payload.len))
	w.bytes(c.payload)
	return w.buf
}

// decode_channel_data reads a framed datagram.
pub fn decode_channel_data(b []u8) !ChannelData {
	mut r := codec.Reader.new(b)
	channel := r.u16('channel number') or {
		return TurnError{
			reason: .bad_message
			detail: 'truncated channel data'
		}
	}
	if channel < channel_min || channel > channel_max {
		return TurnError{
			reason: .bad_message
			detail: 'channel ${channel} is outside the 0x4000-0x7FFF range'
		}
	}
	length := r.u16('length') or {
		return TurnError{
			reason: .bad_message
			detail: 'truncated channel data'
		}
	}
	payload := r.bytes(int(length), 'payload') or {
		return TurnError{
			reason: .bad_message
			detail: 'channel data claims ${length} bytes and carries ${b.len - channel_header_size}'
		}
	}
	return ChannelData{
		channel: channel
		payload: payload
	}
}

// binding is one peer address bound to a channel number.
struct Binding {
mut:
	peer    netaddr.SocketAddr
	channel u16
	// confirmed marks a binding the server has acknowledged. Until then the
	// payload has to go out as a Send indication, because the server would
	// discard channel data for a channel it has not bound.
	confirmed bool
	// refresh_at is when the binding has to be renewed. A channel binding lasts
	// ten minutes and cannot be deleted, only allowed to expire.
	refresh_at i64
}
