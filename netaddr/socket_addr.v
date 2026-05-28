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