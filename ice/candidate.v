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