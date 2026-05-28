module netaddr

// SocketAddr is an IP address and port pair - a transport address in the
// vocabulary of RFC 8445.
pub struct SocketAddr {
pub:
	ip   IpAddr
	port u16
}