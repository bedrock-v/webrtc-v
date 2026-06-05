module stun

import webrtc.netaddr

// STUN encodes an address family in one byte, using values that differ from the
// IP version numbers netaddr uses.
const wire_family_ipv4 = u8(0x01)
const wire_family_ipv6 = u8(0x02)

fn wire_family(f netaddr.Family) u8 {
	return match f {
		.ipv4 { wire_family_ipv4 }
		.ipv6 { wire_family_ipv6 }
	}
}

// encode_address serialises the shared MAPPED-ADDRESS layout: a reserved byte,
// a family byte, a big-endian port and the address octets.
fn encode_address(addr netaddr.SocketAddr) ![]u8 {
	if !addr.is_valid() {
		return EncodeError{
			detail: 'cannot encode an invalid address'
		}
	}
	mut out := []u8{cap: 4 + addr.ip.octets.len}
	out << 0
	out << wire_family(addr.ip.family)
	out << u8(addr.port >> 8)
	out << u8(addr.port)
	out << addr.ip.octets
	return out
}

// decode_address parses the shared MAPPED-ADDRESS layout.
fn decode_address(value []u8) !netaddr.SocketAddr {
	if value.len < 4 {
		return DecodeError{
			reason: .bad_value
			detail: 'address attribute is ${value.len} bytes, needs at least 4'
		}
	}
	family := match value[1] {
		wire_family_ipv4 {
			netaddr.Family.ipv4
		}
		wire_family_ipv6 {
			netaddr.Family.ipv6
		}
		else {
			return DecodeError{
				reason: .bad_value
				detail: 'unknown address family 0x${value[1].hex()}'
			}
		}
	}
	want := family.octet_len()
	if value.len != 4 + want {
		return DecodeError{
			reason: .bad_value
			detail: '${family} address attribute is ${value.len} bytes, expected ${4 + want}'
		}
	}
	port := (u16(value[2]) << 8) | u16(value[3])
	ip := netaddr.IpAddr.from_octets(family, value[4..]) or {
		return DecodeError{
			reason: .bad_value
			detail: err.msg()
		}
	}
	return netaddr.SocketAddr{
		ip:   ip
		port: port
	}
}

// xor_address applies the XOR obfuscation used by XOR-MAPPED-ADDRESS and its
// TURN relatives (RFC 8489 section 14.2).
//
// The obfuscation exists because some NATs rewrite anything in a payload that
// looks like an IP address. XORing with the magic cookie - and, for IPv6, with
// the transaction id as well - keeps the address off the wire in recognisable
// form. It is not encryption: the mask is public and the operation is its own
// inverse, which is why one function serves both directions.
fn xor_address(value []u8, tid [transaction_id_size]u8) []u8 {
	mut mask := []u8{cap: 4 + transaction_id_size}
	mask << u8(magic_cookie >> 24)
	mask << u8(magic_cookie >> 16)
	mask << u8(magic_cookie >> 8)
	mask << u8(magic_cookie)
	mask << tid[..]

	mut out := value.clone()
	// The reserved and family bytes are not obfuscated. The port is XORed with
	// the top 16 bits of the cookie, and the address restarts the mask from the
	// beginning - it is not a continuation of the port's keystream.
	if out.len >= 4 {
		out[2] ^= mask[0]
		out[3] ^= mask[1]
		for j in 0 .. out.len - 4 {
			out[4 + j] ^= mask[j % mask.len]
		}
	}
	return out
}

// mapped_address returns the MAPPED-ADDRESS attribute.
//
// MAPPED-ADDRESS is the pre-RFC-5389 form and is only sent for backward
// compatibility; WebRTC endpoints read XOR-MAPPED-ADDRESS. It is supported here
// because some deployed STUN servers still answer with it alone.
pub fn (m &Message) mapped_address() !netaddr.SocketAddr {
	attr := m.get(attr_mapped_address) or {
		return AttributeNotFoundError{
			typ: attr_mapped_address
		}
	}
	return decode_address(attr.value)!
}

// xor_mapped_address returns the XOR-MAPPED-ADDRESS attribute: the transport
// address the server observed the request coming from, which is what makes a
// server-reflexive ICE candidate possible.
pub fn (m &Message) xor_mapped_address() !netaddr.SocketAddr {
	attr := m.get(attr_xor_mapped_address) or {
		return AttributeNotFoundError{
			typ: attr_xor_mapped_address
		}
	}
	if attr.value.len < 4 {
		return DecodeError{
			reason: .bad_value
			detail: 'XOR-MAPPED-ADDRESS is ${attr.value.len} bytes, needs at least 4'
		}
	}
	return decode_address(xor_address(attr.value, m.transaction_id))!
}

// reflexive_address returns the address the server observed, preferring
// XOR-MAPPED-ADDRESS and falling back to MAPPED-ADDRESS.
pub fn (m &Message) reflexive_address() !netaddr.SocketAddr {
	if addr := m.xor_mapped_address() {
		return addr
	}
	return m.mapped_address()
}

// xor_peer_address returns the TURN XOR-PEER-ADDRESS attribute.
pub fn (m &Message) xor_peer_address() !netaddr.SocketAddr {
	attr := m.get(attr_xor_peer_address) or {
		return AttributeNotFoundError{
			typ: attr_xor_peer_address
		}
	}
	return decode_address(xor_address(attr.value, m.transaction_id))!
}

// xor_relayed_address returns the TURN XOR-RELAYED-ADDRESS attribute: the
// address the relay allocated on the client's behalf.
pub fn (m &Message) xor_relayed_address() !netaddr.SocketAddr {
	attr := m.get(attr_xor_relayed_address) or {
		return AttributeNotFoundError{
			typ: attr_xor_relayed_address
		}
	}
	return decode_address(xor_address(attr.value, m.transaction_id))!
}

// alternate_server returns the ALTERNATE-SERVER attribute sent with a 300 error
// to redirect a client.
pub fn (m &Message) alternate_server() !netaddr.SocketAddr {
	attr := m.get(attr_alternate_server) or {
		return AttributeNotFoundError{
			typ: attr_alternate_server
		}
	}
	return decode_address(attr.value)!
}