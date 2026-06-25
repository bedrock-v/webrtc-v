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

// compute_foundation derives the foundation of a candidate.
//
// RFC 8445 section 5.1.1.3 requires that two candidates share a foundation
// exactly when they have the same type, base address, STUN or TURN server and
// transport. A hash of those four gives that property without having to carry a
// registry of assigned identifiers.
pub fn compute_foundation(typ CandidateType, base netaddr.IpAddr, server string, transport Transport) string {
	digest := sha256.sum('${typ}|${base}|${server}|${transport}'.bytes())
	// Foundations are compared, never interpreted, so a short prefix of the
	// digest is enough and keeps the SDP readable.
	return digest[..8].hex()
}

// str renders the candidate as it appears after "a=candidate:" in SDP
// (RFC 8839 section 5.1).
pub fn (c Candidate) str() string {
	host := if c.hostname != '' { c.hostname } else { c.address.ip.str() }
	mut parts := [c.foundation, c.component.str(), c.transport.str(),
		c.priority.str(), host, c.address.port.str(), 'typ', c.typ.str()]
	if related := c.related {
		parts << ['raddr', related.ip.str(), 'rport', related.port.str()]
	}
	if c.tcp_type != .unspecified {
		parts << ['tcptype', c.tcp_type.str()]
	}
	parts << c.extensions
	return parts.join(' ')
}

// equal reports whether two candidates describe the same thing. Priority is
// excluded: the same address learned twice must compare equal even if the
// second discovery assigned it a different preference.
pub fn (c Candidate) equal(other Candidate) bool {
	return c.component == other.component && c.transport == other.transport && c.typ == other.typ
		&& c.address.equal(other.address)
}

// parse_candidate decodes a candidate attribute value.
//
// The input arrives over signalling from the peer, so every field is validated:
// a malformed candidate is rejected rather than half-parsed, and an address
// that could not be used safely - multicast, or an unspecified address - is
// refused outright.
pub fn parse_candidate(input string) !Candidate {
	if input == '' {
		return CandidateError{
			detail: 'empty candidate'
		}
	}
	if input.len > max_candidate_line_bytes {
		return CandidateError{
			detail: 'candidate line of ${input.len} bytes exceeds the ${max_candidate_line_bytes}-byte limit'
		}
	}
	// Tolerate the "candidate:" prefix, which appears when a caller passes the
	// whole SDP attribute rather than its value.
	mut body := input
	if body.starts_with('candidate:') {
		body = body['candidate:'.len..]
	}

	fields := body.split(' ').filter(it != '')
	if fields.len < 8 {
		return CandidateError{
			detail: 'candidate has ${fields.len} fields, expected at least 8'
		}
	}
	if fields[6] != 'typ' {
		return CandidateError{
			detail: 'expected "typ" in field 7, found "${fields[6]}"'
		}
	}

	foundation := fields[0]
	if foundation.len == 0 || foundation.len > 32 {
		return CandidateError{
			detail: 'foundation must be 1 to 32 characters, got ${foundation.len}'
		}
	}
	component := parse_u32_field(fields[1], 'component')!
	if component < 1 || component > 256 {
		return CandidateError{
			detail: 'component ${component} is outside the 1-256 range'
		}
	}
	transport := match fields[2].to_lower() {
		'udp' {
			Transport.udp
		}
		'tcp' {
			Transport.tcp
		}
		else {
			return CandidateError{
				detail: 'unsupported transport "${fields[2]}"'
			}
		}
	}
	priority := parse_u32_field(fields[3], 'priority')!
	mut hostname := ''
	mut ip := netaddr.IpAddr{}
	if parsed := netaddr.IpAddr.parse(fields[4]) {
		ip = parsed
	} else {
		// RFC 8828: a browser signals a random ".local" name instead of its
		// private addresses. Rejecting it would throw away every local-network
		// path, so it is kept and resolved later.
		if !mdns.is_local_name(fields[4]) {
			return CandidateError{
				detail: 'bad candidate address "${fields[4]}"'
			}
		}
		hostname = fields[4]
	}
	port := parse_u32_field(fields[5], 'port')!
	if port > 65535 {
		return CandidateError{
			detail: 'port ${port} is out of range'
		}
	}
	typ := candidate_type_from_string(fields[7]) or {
		return CandidateError{
			detail: 'unknown candidate type "${fields[7]}"'
		}
	}

	address := netaddr.SocketAddr.new(ip, u16(port))
	if hostname == '' {
		validate_usable_address(address)!
	}

	mut related := ?netaddr.SocketAddr(none)
	mut tcp_type := TcpType.unspecified
	mut extensions := []string{}

	mut i := 8
	for i < fields.len {
		name := fields[i]
		if i + 1 >= fields.len {
			return CandidateError{
				detail: 'extension attribute "${name}" has no value'
			}
		}
		value := fields[i + 1]
		match name {
			'raddr' {
				rport_index := i + 2
				if rport_index + 1 >= fields.len || fields[rport_index] != 'rport' {
					return CandidateError{
						detail: 'raddr must be followed by rport'
					}
				}
				rip := netaddr.IpAddr.parse(value) or {
					return CandidateError{
						detail: 'bad related address: ${err.msg()}'
					}
				}
				rport := parse_u32_field(fields[rport_index + 1], 'rport')!
				if rport > 65535 {
					return CandidateError{
						detail: 'related port ${rport} is out of range'
					}
				}
				related = netaddr.SocketAddr.new(rip, u16(rport))
				i = rport_index + 2
				continue
			}
			'tcptype' {
				tcp_type = match value {
					'active' {
						TcpType.active
					}
					'passive' {
						TcpType.passive
					}
					'so' {
						TcpType.simultaneous_open
					}
					else {
						return CandidateError{
							detail: 'unknown tcptype "${value}"'
						}
					}
				}
			}
			else {
				extensions << name
				extensions << value
			}
		}
		i += 2
	}

	if transport == .tcp && tcp_type == .unspecified {
		return CandidateError{
			detail: 'a TCP candidate must carry a tcptype'
		}
	}

	return Candidate{
		foundation: foundation
		component:  u16(component)
		transport:  transport
		priority:   priority
		address:    address
		typ:        typ
		related:    related
		tcp_type:   tcp_type
		extensions: extensions
		hostname:   hostname
	}
}

// validate_usable_address rejects addresses that cannot be a peer.
//
// A multicast or unspecified address in a candidate is either a bug or an
// attempt to make this agent send traffic somewhere it should not. Refusing
// them here means the checking code never has to consider the possibility.
fn validate_usable_address(addr netaddr.SocketAddr) ! {
	if !addr.is_valid() {
		return CandidateError{
			detail: 'candidate address is malformed'
		}
	}
	if addr.ip.is_multicast() {
		return CandidateError{
			detail: 'multicast address ${addr} cannot be a candidate'
		}
	}
	if addr.ip.is_unspecified() {
		return CandidateError{
			detail: 'unspecified address ${addr} cannot be a candidate'
		}
	}
	if addr.port == 0 {
		return CandidateError{
			detail: 'port 0 cannot be a candidate'
		}
	}
}

fn parse_u32_field(s string, name string) !u32 {
	if s == '' || s.len > 10 {
		return CandidateError{
			detail: '${name} field "${s}" has an invalid length'
		}
	}
	mut value := u64(0)
	for c in s {
		if c < `0` || c > `9` {
			return CandidateError{
				detail: '${name} field "${s}" is not a number'
			}
		}
		value = value * 10 + u64(c - `0`)
		if value > u64(max_u32) {
			return CandidateError{
				detail: '${name} field "${s}" is out of range'
			}
		}
	}
	return u32(value)
}
