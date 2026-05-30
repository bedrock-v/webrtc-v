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