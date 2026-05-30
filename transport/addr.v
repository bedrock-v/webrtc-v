module transport

import net
import webrtc.netaddr

// Package transport bridges netaddr's address values to the standard library's
// sockets.
//
// It exists as its own module so that the protocol codecs - netaddr, stun, rtp,
// rtcp, srtp, sdp - stay free of any dependency on net. Those modules parse and
// build bytes; nothing in them opens a socket. Keeping the split explicit means
// a caller that only needs the codecs never links the networking stack, and it
// keeps the one place that has to know the platform's socket representation
// easy to find.

// socket_addr_from_net converts a standard library socket address.
//
// It goes through the textual form because net.Addr keeps its address bytes in
// a union that is not exported. The formatting net produces - "1.2.3.4:5678"
// and "[::1]:5678" - is exactly what SocketAddr.parse accepts, so the round
// trip is lossless for the IP families; Unix sockets have no equivalent here
// and are rejected.
pub fn socket_addr_from_net(addr net.Addr) !netaddr.SocketAddr {
	family := addr.family()
	if family != .ip && family != .ip6 {
		return error('netaddr: cannot convert a ${family} address to a SocketAddr')
	}
	return netaddr.SocketAddr.parse(addr.str())!
}

// socket_addr_to_net converts to a standard library socket address suitable for sendto.
pub fn socket_addr_to_net(a netaddr.SocketAddr) !net.Addr {
	if !a.is_valid() {
		return error('netaddr: cannot convert an invalid address')
	}
	if a.ip.family == .ipv4 {
		mut octets := [4]u8{}
		for i in 0 .. 4 {
			octets[i] = a.ip.octets[i]
		}
		return net.new_ip(a.port, octets)
	}
	mut octets := [16]u8{}
	for i in 0 .. 16 {
		octets[i] = a.ip.octets[i]
	}
	return net.new_ip6(a.port, octets)
}

// local_addr returns the address a UDP socket is bound to.
//
// ICE needs this after binding to port 0: the kernel picks the port, and the
// host candidate cannot be described until we know which one it chose.
pub fn local_addr(conn &net.UdpConn) !netaddr.SocketAddr {
	bound := conn.sock.address()!
	return socket_addr_from_net(bound)!
}
