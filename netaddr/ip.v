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