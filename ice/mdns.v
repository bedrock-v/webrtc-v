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

// resolve_and_add turns a hostname candidate into an address one and adds it.
fn (mut a Agent) resolve_and_add(candidate Candidate) {
	address := mdns.resolve(candidate.hostname, mdns_timeout) or {
		a.log.debug('could not resolve ${candidate.hostname}: ${err.msg()}')
		return
	}
	if a.is_closed() {
		return
	}

	resolved := Candidate{
		foundation: candidate.foundation
		component:  candidate.component
		transport:  candidate.transport
		priority:   candidate.priority
		address:    netaddr.SocketAddr.new(address, candidate.address.port)
		typ:        candidate.typ
		related:    candidate.related
		tcp_type:   candidate.tcp_type
		extensions: candidate.extensions
	}
	a.log.debug('resolved ${candidate.hostname} to ${address}')
	a.add_remote_candidate(resolved) or {
		a.log.debug('the resolved candidate was refused: ${err.msg()}')
	}
}
