// Package netaddr provides the address types shared by the STUN, ICE and
// PeerConnection layers.
//
// It exists because those layers need addresses as values they can compare,
// hash, sort and serialise, while the standard library's net.Addr is a socket
// address bound to a particular syscall representation. Parsing is written here
// rather than delegated so that hostile input - an SDP candidate line from a
// remote peer, an XOR-MAPPED-ADDRESS from an untrusted STUN server - is handled
// by code that returns errors instead of trusting the platform resolver.
module netaddr

import strings

// Family distinguishes IPv4 from IPv6. The values match the version numbers
// used in textual descriptions; the STUN wire encoding uses different numbers
// and converts at its own boundary.
pub enum Family as u8 {
	ipv4 = 4
	ipv6 = 6
}

pub fn (f Family) str() string {
	return match f {
		.ipv4 { 'IPv4' }
		.ipv6 { 'IPv6' }
	}
}

// octet_len is the size of an address of this family in bytes.
@[inline]
pub fn (f Family) octet_len() int {
	return match f {
		.ipv4 { 4 }
		.ipv6 { 16 }
	}
}

// IpAddr is an IPv4 or IPv6 address.
//
// The address is stored in network byte order. An IPv4 address is kept as four
// octets rather than as an IPv4-mapped IPv6 address, because ICE treats the two
// families as separate candidate pools and silently promoting one to the other
// produces pairs that cannot connect.
pub struct IpAddr {
pub:
	family Family = .ipv4
	octets []u8
	// zone is the scope identifier of a link-local IPv6 address, without the
	// leading '%'. It is part of the address for routing purposes but is never
	// put on the wire.
	zone string
}

// ipv4_unspecified is 0.0.0.0.
pub const ipv4_unspecified = IpAddr{
	family: .ipv4
	octets: [u8(0), 0, 0, 0]
}

// ipv6_unspecified is ::.
pub const ipv6_unspecified = IpAddr{
	family: .ipv6
	octets: []u8{len: 16}
}

// IpAddr.from_octets builds an address from raw bytes, validating the length
// against the family.
pub fn IpAddr.from_octets(family Family, octets []u8) !IpAddr {
	if octets.len != family.octet_len() {
		return error('netaddr: ${family} address needs ${family.octet_len()} octets, got ${octets.len}')
	}
	return IpAddr{
		family: family
		octets: octets.clone()
	}
}

// IpAddr.v4 builds an IPv4 address from its four octets.
pub fn IpAddr.v4(a u8, b u8, c u8, d u8) IpAddr {
	return IpAddr{
		family: .ipv4
		octets: [a, b, c, d]
	}
}

// with_zone returns a copy of the address carrying the given scope identifier.
pub fn (a IpAddr) with_zone(zone string) IpAddr {
	return IpAddr{
		family: a.family
		octets: a.octets
		zone:   zone
	}
}

// is_valid reports whether the address holds the right number of octets. A
// zero-value IpAddr is not valid, which makes an uninitialised field detectable.
@[inline]
pub fn (a IpAddr) is_valid() bool {
	return a.octets.len == a.family.octet_len()
}

// is_unspecified reports whether the address is all zeros (0.0.0.0 or ::).
pub fn (a IpAddr) is_unspecified() bool {
	if !a.is_valid() {
		return false
	}
	for b in a.octets {
		if b != 0 {
			return false
		}
	}
	return true
}

// is_loopback reports whether the address is 127.0.0.0/8 or ::1.
pub fn (a IpAddr) is_loopback() bool {
	if !a.is_valid() {
		return false
	}
	if a.family == .ipv4 {
		return a.octets[0] == 127
	}
	for i in 0 .. 15 {
		if a.octets[i] != 0 {
			return false
		}
	}
	return a.octets[15] == 1
}

// is_link_local reports whether the address is 169.254.0.0/16 or fe80::/10.
// ICE gathers link-local addresses but ranks them below routable ones.
pub fn (a IpAddr) is_link_local() bool {
	if !a.is_valid() {
		return false
	}
	if a.family == .ipv4 {
		return a.octets[0] == 169 && a.octets[1] == 254
	}
	return a.octets[0] == 0xfe && (a.octets[1] & 0xc0) == 0x80
}

// is_private reports whether the address is in a range that is not globally
// routable: RFC 1918 for IPv4, RFC 4193 unique-local for IPv6.
pub fn (a IpAddr) is_private() bool {
	if !a.is_valid() {
		return false
	}
	if a.family == .ipv4 {
		return match true {
			a.octets[0] == 10 { true }
			a.octets[0] == 172 && (a.octets[1] & 0xf0) == 16 { true }
			a.octets[0] == 192 && a.octets[1] == 168 { true }
			else { false }
		}
	}
	return (a.octets[0] & 0xfe) == 0xfc
}

// is_multicast reports whether the address is 224.0.0.0/4 or ff00::/8.
// Multicast addresses are never valid ICE candidates.
pub fn (a IpAddr) is_multicast() bool {
	if !a.is_valid() {
		return false
	}
	if a.family == .ipv4 {
		return (a.octets[0] & 0xf0) == 0xe0
	}
	return a.octets[0] == 0xff
}

// is_ipv4_mapped reports whether an IPv6 address is of the form ::ffff:a.b.c.d.
pub fn (a IpAddr) is_ipv4_mapped() bool {
	if a.family != .ipv6 || !a.is_valid() {
		return false
	}
	for i in 0 .. 10 {
		if a.octets[i] != 0 {
			return false
		}
	}
	return a.octets[10] == 0xff && a.octets[11] == 0xff
}

// unmap converts an IPv4-mapped IPv6 address to its IPv4 form, and returns any
// other address unchanged. Sockets in dual-stack mode report IPv4 peers this
// way, and ICE needs them back in their own family before pairing.
pub fn (a IpAddr) unmap() IpAddr {
	if !a.is_ipv4_mapped() {
		return a
	}
	return IpAddr{
		family: .ipv4
		octets: [a.octets[12], a.octets[13], a.octets[14], a.octets[15]]
	}
}