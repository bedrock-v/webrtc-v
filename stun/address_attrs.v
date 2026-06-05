module stun

import webrtc.netaddr

// STUN encodes an address family in one byte, using values that differ from the
// IP version numbers netaddr uses.
const wire_family_ipv4 = u8(0x01)
const wire_family_ipv6 = u8(0x02)