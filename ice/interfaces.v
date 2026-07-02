module ice

import webrtc.netaddr

// InterfaceOptions filters which local addresses become host candidates.
//
// Every address that becomes a candidate is disclosed to the remote peer and,
// through it, to anyone the peer shares the signalling channel with. That makes
// this filter a privacy control as much as a connectivity one: an endpoint on a
// corporate network that gathers every VLAN address is describing its internal
// topology to whoever is on the other end of the call.
@[params]
pub struct InterfaceOptions {
pub:
	// interfaces, when non-empty, restricts gathering to these interface names.
	interfaces []string
	// include_loopback gathers 127.0.0.0/8 and ::1. Off by default, because a
	// loopback candidate can only pair with the same machine. Tests that run
	// both agents in one process turn it on.
	include_loopback bool
	// include_link_local gathers 169.254.0.0/16 and fe80::/10. These sometimes
	// carry a call between machines on the same segment and are otherwise dead
	// weight in the check list.
	include_link_local bool
	// include_ipv6 gathers IPv6 addresses.
	include_ipv6 bool = true
	// include_ipv4 gathers IPv4 addresses.
	include_ipv4 bool = true
}

// is_candidate_address reports whether an address is usable as a host
// candidate under the given filter.
fn is_candidate_address(addr netaddr.IpAddr, opts InterfaceOptions) bool {
	if !addr.is_valid() {
		return false
	}
	if addr.family == .ipv4 && !opts.include_ipv4 {
		return false
	}
	if addr.family == .ipv6 && !opts.include_ipv6 {
		return false
	}
	// These can never be a peer, whatever the caller asks for.
	if addr.is_unspecified() || addr.is_multicast() {
		return false
	}
	if addr.is_loopback() && !opts.include_loopback {
		return false
	}
	if addr.is_link_local() && !opts.include_link_local {
		return false
	}
	// An IPv4-mapped IPv6 address duplicates an IPv4 address that was gathered
	// separately, and a pair built on one cannot connect.
	if addr.is_ipv4_mapped() {
		return false
	}
	return true
}
