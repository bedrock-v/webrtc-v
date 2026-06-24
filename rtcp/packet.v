module rtcp

import webrtc.internal.codec

// RawPacket holds a packet this implementation does not decode.
//
// Keeping unknown packets rather than discarding them lets an application
// forward a compound datagram intact - which an SFU must do - and lets a new
// feedback type be handled above this package without changing it.
pub struct RawPacket {
pub mut:
	header Header
	body   []u8
}

pub fn (r &RawPacket) destination_ssrc() []u32 {
	// The first word of most packet bodies is a source identifier, but that is
	// a convention rather than a rule, so nothing is claimed for a packet whose
	// layout is unknown.
	return []u32{}
}

pub fn (r &RawPacket) marshal() ![]u8 {
	mut w := codec.Writer.with_capacity(header_size + r.body.len)
	r.header.marshal_into(mut w, r.body.len)!
	w.bytes(r.body)
	return w.buf
}