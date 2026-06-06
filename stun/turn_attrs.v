module stun

import webrtc.internal.codec

// The TURN attributes (RFC 8656).
//
// They are STUN attributes, so they live in the STUN codec next to the rest;
// what uses them is the `turn` module. Keeping the encoding here means the
// relay client is protocol logic with no parsing in it, which is the same split
// the ICE agent and the STUN codec already have.

// max_turn_data is the largest DATA attribute this decoder will accept.
//
// It is the same as the default message limit, so in practice a peer that tries
// to exceed it is stopped by the message bound first. It is stated separately
// because a caller that raises the message limit should not silently raise how
// much a relay can hand back in one datagram.
pub const max_turn_data = 8192

// transport_udp is the REQUESTED-TRANSPORT value for UDP (the IANA protocol
// number). TURN over TCP to the peer is a different allocation type and is not
// supported here.
pub const transport_udp = u8(17)

// lifetime returns the LIFETIME attribute in seconds: how long the server will
// keep an allocation without a refresh.
pub fn (m &Message) lifetime() !u32 {
	attr := m.get(attr_lifetime) or { return AttributeNotFoundError{
		typ: attr_lifetime
	} }
	if attr.value.len != 4 {
		return DecodeError{
			reason: .bad_value
			detail: 'LIFETIME is ${attr.value.len} bytes, expected 4'
		}
	}
	mut r := codec.Reader.new(attr.value)
	return r.u32('LIFETIME')!
}

// add_lifetime sets the requested lifetime. Zero is what deletes an allocation.
pub fn (mut m Message) add_lifetime(seconds u32) {
	mut w := codec.Writer.with_capacity(4)
	w.u32(seconds)
	m.add(attr_lifetime, w.buf)
}

// requested_transport returns the transport an ALLOCATE asks the relay to use
// towards peers.
pub fn (m &Message) requested_transport() !u8 {
	attr := m.get(attr_requested_transport) or {
		return AttributeNotFoundError{
			typ: attr_requested_transport
		}
	}
	if attr.value.len != 4 {
		return DecodeError{
			reason: .bad_value
			detail: 'REQUESTED-TRANSPORT is ${attr.value.len} bytes, expected 4'
		}
	}
	return attr.value[0]
}

// add_requested_transport sets the transport for an ALLOCATE. The last three
// bytes are reserved and must be zero.
pub fn (mut m Message) add_requested_transport(protocol u8) {
	m.add(attr_requested_transport, [protocol, 0, 0, 0])
}