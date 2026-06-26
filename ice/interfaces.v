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