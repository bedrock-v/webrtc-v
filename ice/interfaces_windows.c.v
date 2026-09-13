module ice

import webrtc.netaddr

#flag windows -liphlpapi

#include "@VMODROOT/ice/interfaces_windows.h"

fn C.webrtc_v_get_interface_addresses(&voidptr, &u32) u32

fn C.webrtc_v_free_interface_addresses(voidptr)

fn C.webrtc_v_interface_family(voidptr, u32) int

fn C.webrtc_v_interface_bytes(voidptr, u32) &u8

fn C.webrtc_v_interface_scope_id(voidptr, u32) u32

fn C.webrtc_v_interface_is_up(voidptr, u32) int

fn C.webrtc_v_interface_is_loopback(voidptr, u32) int

fn C.webrtc_v_interface_name(voidptr, u32) &char

fn C.webrtc_v_interface_adapter_name(voidptr, u32) &char

const windows_af_inet = 2
const windows_af_inet6 = 23

// local_interface_addresses enumerates every unicast address on an active
// Windows adapter. Both the friendly interface name and the stable adapter name
// are accepted by InterfaceOptions.interfaces.
pub fn local_interface_addresses(opts InterfaceOptions) ![]netaddr.IpAddr {
	mut addresses := voidptr(unsafe { nil })
	mut count := u32(0)
	status := C.webrtc_v_get_interface_addresses(&addresses, &count)
	if status != 0 {
		return AgentError{
			reason: .transport
			detail: 'GetAdaptersAddresses failed with Windows error ${status}'
		}
	}
	defer {
		C.webrtc_v_free_interface_addresses(addresses)
	}

	mut out := []netaddr.IpAddr{}
	for i in u32(0) .. count {
		if C.webrtc_v_interface_is_up(addresses, i) == 0 {
			continue
		}
		is_loopback_iface := C.webrtc_v_interface_is_loopback(addresses, i) != 0
		if is_loopback_iface && !opts.include_loopback {
			continue
		}

		name := unsafe { cstring_to_vstring(C.webrtc_v_interface_name(addresses, i)) }
		adapter_name := unsafe {
			cstring_to_vstring(C.webrtc_v_interface_adapter_name(addresses, i))
		}
		if opts.interfaces.len > 0 && name !in opts.interfaces && adapter_name !in opts.interfaces {
			continue
		}

		family := match C.webrtc_v_interface_family(addresses, i) {
			windows_af_inet { netaddr.Family.ipv4 }
			windows_af_inet6 { netaddr.Family.ipv6 }
			else { continue }
		}
		mut octets := []u8{len: family.octet_len()}
		unsafe { vmemcpy(octets.data, C.webrtc_v_interface_bytes(addresses, i), octets.len) }
		mut addr := netaddr.IpAddr.from_octets(family, octets) or { continue }
		if family == .ipv6 && addr.is_link_local() {
			scope := C.webrtc_v_interface_scope_id(addresses, i)
			if scope != 0 {
				addr = addr.with_zone(scope.str())
			}
		}
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
