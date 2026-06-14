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

fn test_the_query_asks_for_both_families() {
	query := encode_query('abc.local')!
	mut r := codec.Reader.new(query)
	assert r.u16('id')! == 0
	assert r.u16('flags')! == 0
	assert r.u16('questions')! == 2

	r.skip(6, 'the remaining counts')!
	// First question: the name, then A, then IN with the unicast bit.
	assert r.u8('label length')! == 3
	assert r.bytes(3, 'label')!.bytestr() == 'abc'
	assert r.u8('label length')! == 5
	assert r.bytes(5, 'label')!.bytestr() == 'local'
	assert r.u8('terminator')! == 0
	assert r.u16('type')! == type_a
	class_field := r.u16('class')!
	assert class_field & unicast_response_bit != 0, 'without the unicast bit the answer goes to a port we cannot read'
	assert class_field & 0x7fff == class_in
}

fn test_a_name_with_a_bad_label_is_refused() {
	if _ := encode_name('a..local') {
		assert false, 'an empty label is not encodable'
	}
	long := 'x'.repeat(64)
	if _ := encode_name('${long}.local') {
		assert false, 'a label over 63 bytes is not encodable'
	}
}

fn test_an_answer_is_read() {
	name := 'abc.local'
	response := build_response(name, type_a, [u8(192), 168, 1, 42])!
	address := answer_for(response, name) or {
		assert false, 'the answer should have been found'
		return
	}
	assert address.str() == '192.168.1.42'
}

fn test_an_ipv6_answer_is_read() {
	name := 'abc.local'
	mut body := []u8{len: 16}
	body[0] = 0xfe
	body[1] = 0x80
	body[15] = 0x01
	response := build_response(name, type_aaaa, body)!
	address := answer_for(response, name) or {
		assert false, 'the AAAA answer should have been found'
		return
	}
	assert address.family == .ipv6
	assert address.str() == 'fe80::1'
}

fn test_an_answer_for_another_name_is_ignored() {
	// Every response to every query on the segment arrives here.
	response := build_response('somebody-else.local', type_a, [u8(10), 0, 0, 1])!
	assert answer_for(response, 'abc.local') == none
}

fn test_a_query_is_not_mistaken_for_an_answer() {
	query := encode_query('abc.local')!
	assert answer_for(query, 'abc.local') == none
}