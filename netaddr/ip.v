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