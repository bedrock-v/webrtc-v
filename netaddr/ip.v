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

// equal compares two addresses, including the IPv6 scope identifier.
pub fn (a IpAddr) equal(b IpAddr) bool {
	return a.family == b.family && a.zone == b.zone && a.octets == b.octets
}

// == is defined so addresses can be used as map keys and compared directly.
fn (a IpAddr) == (b IpAddr) bool {
	return a.equal(b)
}

// str formats the address. IPv6 output follows RFC 5952: lowercase hex, the
// longest run of zero groups compressed to '::', ties broken leftmost, and a
// single zero group never compressed.
pub fn (a IpAddr) str() string {
	if !a.is_valid() {
		return '<invalid>'
	}
	if a.family == .ipv4 {
		return '${a.octets[0]}.${a.octets[1]}.${a.octets[2]}.${a.octets[3]}'
	}
	base := format_ipv6(a.octets)
	if a.zone == '' {
		return base
	}
	return '${base}%${a.zone}'
}

fn format_ipv6(octets []u8) string {
	mut groups := []u16{len: 8}
	for i in 0 .. 8 {
		groups[i] = (u16(octets[i * 2]) << 8) | u16(octets[i * 2 + 1])
	}

	mut best_start := -1
	mut best_len := 0
	mut run_start := -1
	mut run_len := 0
	for i in 0 .. 8 {
		if groups[i] == 0 {
			if run_start < 0 {
				run_start = i
				run_len = 0
			}
			run_len++
			if run_len > best_len {
				best_len = run_len
				best_start = run_start
			}
		} else {
			run_start = -1
			run_len = 0
		}
	}
	// A run of one is written out in full; '::' must save at least two groups.
	if best_len < 2 {
		best_start = -1
		best_len = 0
	}

	// An IPv4-mapped address is conventionally printed with a dotted tail. Every
	// other stack emits it that way, and it is what an operator reading a log
	// expects to see.
	if best_start == 0 && best_len == 5 && groups[5] == 0xffff {
		return '::ffff:${octets[12]}.${octets[13]}.${octets[14]}.${octets[15]}'
	}

	mut sb := strings.new_builder(45)
	mut i := 0
	for i < 8 {
		if best_start >= 0 && i == best_start {
			sb.write_string('::')
			i += best_len
			continue
		}
		// A separator is needed before every group except the first, and except
		// immediately after a '::' that already supplied one.
		if i > 0 && !(best_start >= 0 && i == best_start + best_len) {
			sb.write_string(':')
		}
		sb.write_string(groups[i].hex())
		i++
	}
	return sb.str()
}

// IpAddr.parse parses a textual IPv4 or IPv6 address.
//
// It accepts exactly the forms this stack must interoperate with and nothing
// else: no hostnames, no DNS, and no leading zeros in IPv4 octets, which some
// resolvers read as octal.
pub fn IpAddr.parse(s string) !IpAddr {
	if s == '' {
		return error('netaddr: empty address')
	}
	if s.contains(':') {
		return parse_ipv6(s)
	}
	return parse_ipv4(s)
}

fn parse_ipv4(s string) !IpAddr {
	parts := s.split('.')
	if parts.len != 4 {
		return error('netaddr: ${s} is not a dotted-quad IPv4 address')
	}
	mut octets := []u8{len: 4}
	for i, part in parts {
		if part.len == 0 || part.len > 3 {
			return error('netaddr: bad IPv4 octet ${i} in ${s}')
		}
		if part.len > 1 && part[0] == `0` {
			// "010" is 8 to a C resolver and 10 to a human. Rejecting the form
			// removes an entire class of address-confusion bug.
			return error('netaddr: IPv4 octet ${i} in ${s} has a leading zero')
		}
		mut value := 0
		for c in part {
			if c < `0` || c > `9` {
				return error('netaddr: non-digit in IPv4 octet ${i} of ${s}')
			}
			value = value * 10 + int(c - `0`)
		}
		if value > 255 {
			return error('netaddr: IPv4 octet ${i} of ${s} is out of range')
		}
		octets[i] = u8(value)
	}
	return IpAddr{
		family: .ipv4
		octets: octets
	}
}

fn parse_ipv6(input string) !IpAddr {
	mut s := input
	mut zone := ''
	if idx := s.index('%') {
		zone = s[idx + 1..]
		s = s[..idx]
		if zone == '' {
			return error('netaddr: empty IPv6 zone in ${input}')
		}
	}
	if s == '' {
		return error('netaddr: empty IPv6 address')
	}
	// A colon may only appear doubled at either end. Rejecting the single-colon
	// forms up front is what keeps ":1" from being read as "::1".
	if s.starts_with(':') && !s.starts_with('::') {
		return error('netaddr: ${input} starts with a single colon')
	}
	if s.ends_with(':') && !s.ends_with('::') {
		return error('netaddr: ${input} ends with a single colon')
	}

	// A trailing dotted-quad (::ffff:1.2.3.4) is rewritten into the two hex
	// groups it stands for, so the scanner below has only one syntax to handle.
	if s.contains('.') {
		last_colon := s.last_index(':') or {
			return error('netaddr: ${input} is not an IPv6 address')
		}
		v4 := parse_ipv4(s[last_colon + 1..])!
		hi := ((u32(v4.octets[0]) << 8) | u32(v4.octets[1])).hex()
		lo := ((u32(v4.octets[2]) << 8) | u32(v4.octets[3])).hex()
		s = '${s[..last_colon + 1]}${hi}:${lo}'
	}

	if s == '::' {
		return IpAddr{
			family: .ipv6
			octets: []u8{len: 16}
			zone:   zone
		}
	}

	// Collapsing the doubled colon at either end to a single one leaves exactly
	// one empty token marking the '::' position after splitting.
	mut work := s
	if work.starts_with('::') {
		work = work[1..]
	}
	if work.ends_with('::') {
		work = work[..work.len - 1]
	}

	mut head := []u16{cap: 8}
	mut back := []u16{cap: 8}
	mut seen_double := false
	for part in work.split(':') {
		if part.len == 0 {
			if seen_double {
				return error('netaddr: ${input} has more than one ::')
			}
			seen_double = true
			continue
		}
		if part.len > 4 {
			return error('netaddr: IPv6 group "${part}" in ${input} is longer than 4 digits')
		}
		mut group := u16(0)
		for c in part {
			d := hex_digit(c) or {
				return error('netaddr: bad hex digit in IPv6 group "${part}" of ${input}')
			}
			group = (group << 4) | u16(d)
		}
		if seen_double {
			back << group
		} else {
			head << group
		}
	}

	total := head.len + back.len
	if seen_double {
		// '::' stands for at least one group of zeros.
		if total > 7 {
			return error('netaddr: ${input} has ${total} groups, too many for ::')
		}
	} else if total != 8 {
		return error('netaddr: ${input} has ${total} groups, expected 8')
	}

	mut octets := []u8{len: 16}
	mut pos := 0
	for g in head {
		octets[pos] = u8(g >> 8)
		octets[pos + 1] = u8(g)
		pos += 2
	}
	pos += (8 - total) * 2
	for g in back {
		octets[pos] = u8(g >> 8)
		octets[pos + 1] = u8(g)
		pos += 2
	}
	return IpAddr{
		family: .ipv6
		octets: octets
		zone:   zone
	}
}