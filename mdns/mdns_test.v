module mdns

import webrtc.internal.codec
import webrtc.netaddr

// Tests for the resolver.
//
// The query goes to a link-local multicast group, so a test that actually
// resolves would depend on what else is on the network. What is tested here is
// everything either side of the socket: the query this resolver builds, and
// what it makes of a response - including the responses designed to break it.

fn test_a_local_name_is_recognised() {
	assert is_local_name('d4f4c2b0-0000-4000-8000-000000000000.local')
	assert is_local_name('HOST.LOCAL')
	assert is_local_name('host.local.')
	assert !is_local_name('example.com')
	assert !is_local_name('192.168.1.1')
	assert !is_local_name('localhost')
}

fn test_a_name_that_is_not_local_is_refused() {
	// Not an error about the network: this resolver only speaks for .local, and
	// saying so is more useful than timing out.
	if _ := resolve('example.com', 10 * 1000000) {
		assert false, 'only .local names belong here'
	} else {
		assert err is MdnsError
		if err is MdnsError {
			assert err.reason == .not_local
		}
	}
}