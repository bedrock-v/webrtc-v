module turn

import net
import sync
import time
import webrtc.logging
import webrtc.netaddr
import webrtc.stun
import webrtc.transport

// The relay client.
//
// One socket to the relay carries everything: the transactions that set the
// allocation up, and the relayed traffic itself. A reader thread owns the
// socket and sorts what arrives - a response goes to whoever is waiting for
// that transaction, relayed data goes to the application - which is the same
// arrangement the ICE agent uses, for the same reason: the ordering rules end
// up in one place.

// max_datagram is the largest datagram read from the relay. A relayed payload
// is bounded by the DATA attribute limit, and the framing adds a little.
const max_datagram = 9216

// default_lifetime is the allocation lifetime to ask for. RFC 8656 says a
// server may return less, and the refresh schedule follows what it returns
// rather than what was asked.
pub const default_lifetime = u32(600)

// Packet is one datagram relayed from a peer.
pub struct Packet {
pub:
	from netaddr.SocketAddr
	data []u8
}