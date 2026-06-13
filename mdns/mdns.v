// Package mdns resolves the ".local" names that appear in ICE candidates.
//
// A browser does not put its private addresses in an offer any more. It
// registers a random name like "d4f4c2b0-....local" with multicast DNS and
// signals that instead (RFC 8828). A peer that cannot resolve the name loses
// the host candidate, and with it every local-network path - which is usually
// the fastest one there is.
//
// This is a resolver only. Being a responder means registering a name and
// answering queries for it, which is what the privacy half of RFC 8828 needs;
// it is not implemented, so this end's own candidates carry addresses.
module mdns

import net
import time
import webrtc.internal.codec
import webrtc.netaddr
import webrtc.transport