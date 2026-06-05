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