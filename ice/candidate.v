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