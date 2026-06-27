module ice

import net
import webrtc.netaddr
import webrtc.transport

// Windows has no getifaddrs. Enumerating adapters properly means calling
// GetAdaptersAddresses and walking a linked list of variable-length records,
// which is on the roadmap; until then this fallback finds the address the
// routing table would actually use.
//
// The trick is that connecting a UDP socket performs no I/O - it only fixes the
// destination, which makes the kernel choose a source address and bind to it.
// Reading that address back gives the primary address for each family without a
// packet leaving the machine.
//
// The limitation is real and worth stating plainly: on a multi-homed host this
// finds one address per family rather than all of them, so a path that would
// only work over a secondary interface will not be discovered. Server-reflexive
// candidates still work, because they are gathered from these same sockets.
const probe_targets = {
	'ipv4': '198.51.100.1:9'
	'ipv6': '[2001:db8::1]:9'
}