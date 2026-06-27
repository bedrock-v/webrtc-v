module ice

import webrtc.netaddr

// Only ifaddrs.h is included here. It pulls in the socket address definitions
// itself, and adding sys/socket.h or net/if.h alongside it makes V emit the
// includes ahead of its own runtime declarations, which fails to compile.
#include <ifaddrs.h>

// Enumerating local addresses has no portable answer in V's standard library,
// so it is done here through getifaddrs, which every Unix provides.
//
// The layout of struct sockaddr differs between Linux and the BSDs - the BSDs
// put a length byte where Linux puts the low half of the family - so the family
// is read through a platform-conditional helper rather than a struct field.
// The address bytes themselves sit at the same offset either way, because the
// port field absorbs the difference.

// ifa_addr is typed as voidptr rather than &C.sockaddr because the net module
// already declares the sockaddr family of structs; redeclaring them here would
// collide at the C level. Nothing is lost - the fields are read by offset
// anyway, which is what makes the BSD and Linux layouts interchangeable.
struct C.ifaddrs {
	ifa_next  &C.ifaddrs
	ifa_name  &char
	ifa_flags u32
	ifa_addr  voidptr
}

fn C.getifaddrs(ifap &&C.ifaddrs) int
fn C.freeifaddrs(ifa &C.ifaddrs)

// The interface flags are spelled out rather than taken from net/if.h. Adding
// that header makes V emit the include ahead of its own runtime declarations,
// and these two values have been 0x1 and 0x8 on every Unix since 4.3BSD.
const iff_up = u32(0x1)
const iff_loopback = u32(0x8)

// sockaddr_family reads the address family out of a struct sockaddr.
fn sockaddr_family(sa voidptr) int {
	if sa == unsafe { nil } {
		return 0
	}
	$if macos || darwin || freebsd || openbsd || netbsd || dragonfly {
		// BSD: struct sockaddr starts with a one-byte length, then a one-byte
		// family.
		return int(unsafe { (&u8(sa))[1] })
	} $else {
		return int(unsafe { *(&u16(sa)) })
	}
}

// sockaddr_to_ip extracts the address from a struct sockaddr_in or
// sockaddr_in6. The IPv4 address is at offset 4 and the IPv6 address at offset
// 8 on every platform this compiles for.
fn sockaddr_to_ip(sa voidptr) ?netaddr.IpAddr {
	family := sockaddr_family(sa)
	base := unsafe { &u8(sa) }
	if family == C.AF_INET {
		mut octets := []u8{len: 4}
		unsafe { vmemcpy(octets.data, base + 4, 4) }
		return netaddr.IpAddr.from_octets(.ipv4, octets) or { return none }
	}
	if family == C.AF_INET6 {
		mut octets := []u8{len: 16}
		unsafe { vmemcpy(octets.data, base + 8, 16) }
		mut addr := netaddr.IpAddr.from_octets(.ipv6, octets) or { return none }
		// The scope identifier follows the 16 address bytes. It only carries
		// meaning for link-local addresses, where it names the interface the
		// address is valid on.
		if addr.is_link_local() {
			scope := unsafe { *(&u32(base + 24)) }
			if scope != 0 {
				addr = addr.with_zone(scope.str())
			}
		}
		return addr
	}
	return none
}

// local_interface_addresses returns the usable addresses of every up,
// non-loopback interface.
//
// Loopback is excluded unless asked for: a loopback candidate can only ever
// pair with the same machine, so offering one to a remote peer leaks the fact
// that the address exists without any chance of connecting. Tests that run both
// agents in one process do want it, which is why it is an option rather than a
// rule.
pub fn local_interface_addresses(opts InterfaceOptions) ![]netaddr.IpAddr {
	mut list := &C.ifaddrs(unsafe { nil })
	if C.getifaddrs(&list) != 0 {
		return AgentError{
			reason: .transport
			detail: 'getifaddrs failed'
		}
	}
	defer {
		C.freeifaddrs(list)
	}

	mut out := []netaddr.IpAddr{}
	mut node := list
	for node != unsafe { nil } {
		current := node
		node = current.ifa_next

		if current.ifa_addr == unsafe { nil } {
			continue
		}
		if current.ifa_flags & iff_up == 0 {
			continue
		}
		is_loopback_iface := current.ifa_flags & iff_loopback != 0
		if is_loopback_iface && !opts.include_loopback {
			continue
		}

		name := unsafe { cstring_to_vstring(current.ifa_name) }
		if opts.interfaces.len > 0 && name !in opts.interfaces {
			continue
		}

		addr := sockaddr_to_ip(current.ifa_addr) or { continue }
		if !is_candidate_address(addr, opts) {
			continue
		}
		if out.any(it.equal(addr)) {
			continue
		}
		out << addr
	}
	return out
}
