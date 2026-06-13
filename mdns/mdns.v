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

// multicast_group_v4 and multicast_group_v6 are where a query goes. Both are
// link-local, so a query never leaves the network segment.
pub const multicast_group_v4 = '224.0.0.251:5353'
pub const multicast_group_v6 = '[ff02::fb]:5353'

// max_response is the largest response accepted. A multicast DNS response
// carrying an address is a few hundred bytes; anything much larger is either
// not for us or is trying to make us do work.
pub const max_response = 4096

// max_name_labels bounds how many labels a name may have, and
// max_pointer_hops bounds how many compression pointers are followed. Both stop
// a crafted response from making the parser loop: a pointer that points at
// itself is the classic decompression bomb.
const max_name_labels = 128
const max_pointer_hops = 16

// record types and classes, the only ones this resolver uses.
const type_a = u16(1)
const type_aaaa = u16(28)
const class_in = u16(1)

// unicast_response_bit asks the responder to answer directly to the querier's
// port rather than to the multicast group.
//
// Without it the answer goes to the group on port 5353, which can only be read
// by a socket bound to that port - and on most machines that port already
// belongs to the system responder. Setting it is what lets this work as an
// ordinary client. A responder that ignores the bit will not be heard, which is
// the known limit of this approach.
const unicast_response_bit = u16(0x8000)