module netaddr

// SocketAddr is an IP address and port pair - a transport address in the
// vocabulary of RFC 8445.
pub struct SocketAddr {
pub:
	ip   IpAddr
	port u16
}

// SocketAddr.new pairs an address with a port.
pub fn SocketAddr.new(ip IpAddr, port u16) SocketAddr {
	return SocketAddr{
		ip:   ip
		port: port
	}
}

// is_valid reports whether the address part is well formed.
@[inline]
pub fn (a SocketAddr) is_valid() bool {
	return a.ip.is_valid()
}

// family returns the address family of the IP part.
@[inline]
pub fn (a SocketAddr) family() Family {
	return a.ip.family
}

// unmap converts an IPv4-mapped IPv6 socket address to its IPv4 form.
pub fn (a SocketAddr) unmap() SocketAddr {
	return SocketAddr{
		ip:   a.ip.unmap()
		port: a.port
	}
}

pub fn (a SocketAddr) equal(b SocketAddr) bool {
	return a.port == b.port && a.ip.equal(b.ip)
}

fn (a SocketAddr) == (b SocketAddr) bool {
	return a.equal(b)
}

// str formats the pair as host:port, bracketing IPv6 hosts so the port stays
// unambiguous.
pub fn (a SocketAddr) str() string {
	if a.ip.family == .ipv6 {
		return '[${a.ip}]:${a.port}'
	}
	return '${a.ip}:${a.port}'
}

// SocketAddr.parse parses "host:port", with IPv6 hosts in square brackets.
pub fn SocketAddr.parse(s string) !SocketAddr {
	if s == '' {
		return error('netaddr: empty socket address')
	}
	mut host := ''
	mut port_str := ''
	if s[0] == `[` {
		close := s.index(']') or { return error('netaddr: unterminated [ in ${s}') }
		host = s[1..close]
		rest := s[close + 1..]
		if !rest.starts_with(':') {
			return error('netaddr: ${s} is missing a port')
		}
		port_str = rest[1..]
	} else {
		idx := s.last_index(':') or { return error('netaddr: ${s} is missing a port') }
		host = s[..idx]
		port_str = s[idx + 1..]
		if host.contains(':') {
			return error('netaddr: bare IPv6 host in ${s} must be bracketed')
		}
	}
	ip := IpAddr.parse(host)!
	port := parse_port(port_str) or { return error('netaddr: bad port in ${s}: ${err.msg()}') }
	return SocketAddr{
		ip:   ip
		port: port
	}
}

fn parse_port(s string) !u16 {
	if s == '' || s.len > 5 {
		return error('port "${s}" has an invalid length')
	}
	mut value := u32(0)
	for c in s {
		if c < `0` || c > `9` {
			return error('port "${s}" contains a non-digit')
		}
		value = value * 10 + u32(c - `0`)
	}
	if value > 65535 {
		return error('port ${value} is out of range')
	}
	return u16(value)
}
