module ice

import time
import webrtc.mdns
import webrtc.netaddr

// Resolving the ".local" candidates of RFC 8828.
//
// A browser no longer signals its private addresses. It registers a random name
// with multicast DNS and signals that, so the address is only learned by
// anything on the same network segment - which is exactly the set of peers that
// could reach it anyway. A peer that cannot resolve the name simply loses that
// path.

// mdns_timeout bounds one resolution. It is short because a name that does not
// resolve is the common case - the peer may be on another network entirely -
// and every candidate that cannot be resolved is one connection attempt still
// waiting.
const mdns_timeout = 2 * time.second