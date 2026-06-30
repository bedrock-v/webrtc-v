// Package ice implements Interactive Connectivity Establishment (RFC 8445) and
// the SDP encoding of candidates (RFC 8839).
//
// ICE is how two endpoints behind NATs find a path to each other. Each side
// gathers the transport addresses it might be reachable on, exchanges them
// through signalling, and then probes every pairing with STUN until one works.
// The probes double as authentication: they carry a MESSAGE-INTEGRITY keyed
// with credentials that only the signalling channel could have carried, so an
// off-path attacker cannot answer them.
module ice

import crypto.sha256
import webrtc.netaddr
import webrtc.mdns

// CandidateType is how a candidate address was learned. The order of the
// variants matches their default preference, most preferred first.
pub enum CandidateType {
	// host: an address on a local interface. Reachable only if the peer is on
	// the same network or the address is globally routable.
	host
	// peer_reflexive: an address a peer observed a check arriving from, which
	// the local agent did not know it had. Discovered during checking, never
	// gathered.
	peer_reflexive
	// server_reflexive: an address a STUN server observed. This is the outside
	// of the NAT, and it is what usually works.
	server_reflexive
	// relayed: an address allocated on a TURN server, which forwards traffic.
	// Always works, and always costs the relay's bandwidth, so it is the last
	// resort.
	relayed
}

pub fn (t CandidateType) str() string {
	return match t {
		.host { 'host' }
		.peer_reflexive { 'prflx' }
		.server_reflexive { 'srflx' }
		.relayed { 'relay' }
	}
}

pub fn candidate_type_from_string(s string) ?CandidateType {
	return match s {
		'host' { CandidateType.host }
		'prflx' { CandidateType.peer_reflexive }
		'srflx' { CandidateType.server_reflexive }
		'relay' { CandidateType.relayed }
		else { none }
	}
}

// preference is the type preference used in the priority formula
// (RFC 8445 section 5.1.2.2). Higher is better.
pub fn (t CandidateType) preference() u32 {
	return match t {
		.host { 126 }
		.peer_reflexive { 110 }
		.server_reflexive { 100 }
		.relayed { 0 }
	}
}

// Transport is the protocol a candidate uses.
pub enum Transport {
	udp
	tcp
}

pub fn (t Transport) str() string {
	return match t {
		.udp { 'udp' }
		.tcp { 'tcp' }
	}
}

// TcpType distinguishes the roles of an ICE-TCP candidate (RFC 6544).
pub enum TcpType {
	unspecified
	active
	passive
	simultaneous_open
}

pub fn (t TcpType) str() string {
	return match t {
		.unspecified { '' }
		.active { 'active' }
		.passive { 'passive' }
		.simultaneous_open { 'so' }
	}
}

// component_rtp and component_rtcp are the component identifiers of RFC 8445
// section 4.1.1.1. With rtcp-mux, which every WebRTC endpoint uses, only the
// RTP component exists.
pub const component_rtp = u16(1)
pub const component_rtcp = u16(2)

// max_candidate_line_bytes bounds a candidate attribute from signalling. The
// peer controls this string, so its length is not to be trusted.
pub const max_candidate_line_bytes = 1024

// Candidate is one transport address an agent might be reachable at.
pub struct Candidate {
pub:
	// foundation groups candidates that would behave the same way, so that a
	// check failing on one predicts failure on the others. Candidates share a
	// foundation when their type, base address, server and transport match.
	foundation string
	// component is which part of the media stream this candidate carries.
	component u16 = component_rtp
	transport Transport
	priority  u32
	address   netaddr.SocketAddr
	typ       CandidateType
	// related is the address a derived candidate came from: the base for a
	// reflexive candidate, the mapped address for a relayed one. It is
	// diagnostic only and must never be used to route.
	related  ?netaddr.SocketAddr
	tcp_type TcpType
	// extensions preserves unrecognised attributes so a candidate survives a
	// parse and re-serialise.
	extensions []string
	// hostname is set when the candidate named a ".local" host instead of an
	// address (RFC 8828). The address is meaningless until multicast DNS has
	// resolved it, and `address` stays zero in the meantime.
	hostname string
}

// needs_resolution reports whether this candidate names a host rather than an
// address.
@[inline]
pub fn (c &Candidate) needs_resolution() bool {
	return c.hostname != ''
}

// compute_priority returns the priority of a candidate (RFC 8445 section
// 5.1.2.1).
//
//	priority = 2^24 * type preference + 2^8 * local preference + (256 - component)
//
// The three terms are laid out so that type dominates: any host candidate
// outranks any server-reflexive one, whatever the local preference. That is
// deliberate - it makes the checks that are cheapest and lowest latency happen
// first.
pub fn compute_priority(typ CandidateType, local_preference u16, component u16) u32 {
	return (typ.preference() << 24) | (u32(local_preference) << 8) | (256 - u32(component))
}

// default_local_preference returns a local preference that ranks IPv6 above
// IPv4 and routable addresses above link-local ones.
//
// RFC 8445 leaves the value to the implementation. Preferring IPv6 follows
// RFC 8445 section 5.1.2.2, and demoting link-local addresses keeps checks that
// can only succeed on the same link from delaying ones that might reach the
// wider network.
pub fn default_local_preference(addr netaddr.IpAddr) u16 {
	mut preference := u16(0)
	if addr.family == .ipv6 {
		preference += 40000
	} else {
		preference += 20000
	}
	if addr.is_link_local() {
		preference -= 15000
	} else if addr.is_loopback() {
		preference -= 18000
	} else if !addr.is_private() {
		preference += 10000
	}
	return preference
}