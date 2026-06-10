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