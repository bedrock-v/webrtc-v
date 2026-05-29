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