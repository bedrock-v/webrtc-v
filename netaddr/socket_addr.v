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