module stun

import webrtc.netaddr

// STUN encodes an address family in one byte, using values that differ from the
// IP version numbers netaddr uses.
const wire_family_ipv4 = u8(0x01)
const wire_family_ipv6 = u8(0x02)

fn wire_family(f netaddr.Family) u8 {
	return match f {
		.ipv4 { wire_family_ipv4 }
		.ipv6 { wire_family_ipv6 }
	}
}