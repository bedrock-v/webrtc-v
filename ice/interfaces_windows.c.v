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

pub fn local_interface_addresses(opts InterfaceOptions) ![]netaddr.IpAddr {
	mut out := []netaddr.IpAddr{}

	for family, target in probe_targets {
		if family == 'ipv4' && !opts.include_ipv4 {
			continue
		}
		if family == 'ipv6' && !opts.include_ipv6 {
			continue
		}
		mut conn := net.dial_udp(target) or { continue }
		addr := transport.local_addr(conn) or {
			conn.close() or {}
			continue
		}
		conn.close() or {}

		if !is_candidate_address(addr.ip, opts) {
			continue
		}
		if out.any(it.equal(addr.ip)) {
			continue
		}
		out << addr.ip
	}

	if opts.include_loopback {
		for candidate in [netaddr.IpAddr.parse('127.0.0.1') or { netaddr.ipv4_unspecified },
			netaddr.IpAddr.parse('::1') or { netaddr.ipv6_unspecified }] {
			if !is_candidate_address(candidate, opts) {
				continue
			}
			if out.any(it.equal(candidate)) {
				continue
			}
			out << candidate
		}
	}

	return out
}
