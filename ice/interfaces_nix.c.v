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