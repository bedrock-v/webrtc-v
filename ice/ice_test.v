module ice

import time
import webrtc.netaddr

fn test_candidate_parse_and_render_round_trip() {
	lines := [
		'1467250027 1 udp 2122260223 192.168.0.196 46243 typ host',
		'1467250027 2 udp 2122260222 192.168.0.196 56280 typ host',
		'647372371 1 udp 1685987071 88.99.104.5 46243 typ srflx raddr 192.168.0.196 rport 46243',
		'123 1 udp 41885439 10.0.0.1 3478 typ relay raddr 88.99.104.5 rport 46243',
		'abc 1 tcp 2105458943 192.168.0.196 9 typ host tcptype active',
		'f1 1 udp 100 2001:db8::1 5000 typ host',
	]
	for line in lines {
		candidate := parse_candidate(line)!
		assert candidate.str() == line, 'round trip changed "${line}" into "${candidate.str()}"'
	}
}

fn test_candidate_accepts_the_sdp_prefix() {
	with_prefix := parse_candidate('candidate:1 1 udp 100 1.2.3.4 5000 typ host')!
	without := parse_candidate('1 1 udp 100 1.2.3.4 5000 typ host')!
	assert with_prefix.str() == without.str()
}

fn test_candidate_fields() {
	candidate :=
		parse_candidate('647372371 1 udp 1685987071 88.99.104.5 46243 typ srflx raddr 192.168.0.196 rport 46243')!
	assert candidate.foundation == '647372371'
	assert candidate.component == 1
	assert candidate.transport == .udp
	assert candidate.priority == 1685987071
	assert candidate.address.str() == '88.99.104.5:46243'
	assert candidate.typ == .server_reflexive
	related := candidate.related?
	assert related.str() == '192.168.0.196:46243'
}

fn test_candidate_preserves_unknown_extensions() {
	line := '1 1 udp 100 1.2.3.4 5000 typ host generation 0 ufrag abcd network-id 3'
	candidate := parse_candidate(line)!
	assert candidate.str() == line
}

fn test_candidate_rejects_malformed_input() {
	bad := {
		'empty':                 ''
		'too few fields':        '1 1 udp 100 1.2.3.4 5000 typ'
		'missing typ keyword':   '1 1 udp 100 1.2.3.4 5000 xyz host'
		'unknown type':          '1 1 udp 100 1.2.3.4 5000 typ nonsense'
		'unknown transport':     '1 1 sctp 100 1.2.3.4 5000 typ host'
		'bad address':           '1 1 udp 100 999.1.1.1 5000 typ host'
		'bad port':              '1 1 udp 100 1.2.3.4 70000 typ host'
		'port zero':             '1 1 udp 100 1.2.3.4 0 typ host'
		'non numeric priority':  '1 1 udp abc 1.2.3.4 5000 typ host'
		'component zero':        '1 0 udp 100 1.2.3.4 5000 typ host'
		'component too large':   '1 300 udp 100 1.2.3.4 5000 typ host'
		'raddr without rport':   '1 1 udp 100 1.2.3.4 5000 typ srflx raddr 1.1.1.1'
		'dangling extension':    '1 1 udp 100 1.2.3.4 5000 typ host generation'
		'tcp without tcptype':   '1 1 tcp 100 1.2.3.4 9 typ host'
		'unknown tcptype':       '1 1 tcp 100 1.2.3.4 9 typ host tcptype sideways'
		'empty foundation':      ' 1 udp 100 1.2.3.4 5000 typ host'
		'priority out of range': '1 1 udp 99999999999 1.2.3.4 5000 typ host'
	}
	for name, line in bad {
		if _ := parse_candidate(line) {
			assert false, 'expected "${name}" to be rejected'
		} else {
			assert err is CandidateError, '"${name}" produced ${err}'
		}
	}
}

fn test_candidate_rejects_unroutable_addresses() {
	// A multicast or unspecified address in a candidate is either a bug or an
	// attempt to make this agent send traffic somewhere it should not.
	for line in ['1 1 udp 100 224.0.0.1 5000 typ host', '1 1 udp 100 0.0.0.0 5000 typ host',
		'1 1 udp 100 ff02::1 5000 typ host', '1 1 udp 100 :: 5000 typ host'] {
		parse_candidate(line) or { continue }
		assert false, 'expected ${line} to be rejected'
	}
}

fn test_candidate_line_length_is_bounded() {
	long := '1 1 udp 100 1.2.3.4 5000 typ host' + ' x y'.repeat(400)
	parse_candidate(long) or { return }
	assert false, 'an over-long candidate line must be rejected'
}

fn test_priority_formula() {
	// RFC 8445 section 5.1.2.1.
	assert compute_priority(.host, 65535, 1) == (126 << 24) | (65535 << 8) | 255
	assert compute_priority(.server_reflexive, 0, 1) == (100 << 24) | 255
	assert compute_priority(.relayed, 0, 1) == 255

	// Type dominates: any host candidate outranks any reflexive one.
	assert compute_priority(.host, 0, 1) > compute_priority(.server_reflexive, 65535, 1)
	assert compute_priority(.server_reflexive, 0, 1) > compute_priority(.relayed, 65535, 1)
	// A lower component number is preferred.
	assert compute_priority(.host, 100, 1) > compute_priority(.host, 100, 2)
}

fn test_local_preference_ordering() {
	global_v6 := default_local_preference(netaddr.IpAddr.parse('2001:db8::1')!)
	global_v4 := default_local_preference(netaddr.IpAddr.parse('8.8.8.8')!)
	private_v4 := default_local_preference(netaddr.IpAddr.parse('192.168.1.1')!)
	link_local := default_local_preference(netaddr.IpAddr.parse('169.254.1.1')!)
	loopback := default_local_preference(netaddr.IpAddr.parse('127.0.0.1')!)

	assert global_v6 > global_v4
	assert global_v4 > private_v4
	assert private_v4 > link_local
	assert link_local > loopback
}

fn test_foundation_groups_equivalent_candidates() {
	base := netaddr.IpAddr.parse('192.168.1.1')!
	other := netaddr.IpAddr.parse('192.168.1.2')!

	same := compute_foundation(.host, base, '', .udp)
	assert compute_foundation(.host, base, '', .udp) == same
	// A different type, base, server or transport must give a different
	// foundation, or unrelated pairs would be frozen against each other.
	assert compute_foundation(.server_reflexive, base, '', .udp) != same
	assert compute_foundation(.host, other, '', .udp) != same
	assert compute_foundation(.host, base, 'stun.example:3478', .udp) != same
	assert compute_foundation(.host, base, '', .tcp) != same
}

fn make_pair(local_priority u32, remote_priority u32) !CandidatePair {
	return CandidatePair{
		local:  Candidate{
			priority: local_priority
			address:  netaddr.SocketAddr.parse('1.1.1.1:1')!
		}
		remote: Candidate{
			priority: remote_priority
			address:  netaddr.SocketAddr.parse('2.2.2.2:2')!
		}
	}
}

fn test_pair_priority_is_symmetric_between_agents() {
	// Both agents must derive the same ordering from the same two priorities,
	// or they would work through the check list out of step.
	pair := make_pair(100, 200)!
	mirrored := CandidatePair{
		local:  pair.remote
		remote: pair.local
	}
	assert pair.priority(true) == mirrored.priority(false)
	assert pair.priority(false) == mirrored.priority(true)
}

fn test_pair_priority_formula() {
	pair := make_pair(100, 200)!
	// 2^32 * min(G,D) + 2 * max(G,D) + (G > D)
	assert pair.priority(true) == (u64(100) << 32) + 400 + 0
	assert pair.priority(false) == (u64(100) << 32) + 400 + 1
}

fn test_pair_ordering_is_by_descending_priority() {
	mut pairs := [make_pair(10, 10)!, make_pair(300, 300)!, make_pair(50, 50)!]
	sort_pairs(mut pairs, true)
	assert pairs[0].local.priority == 300
	assert pairs[1].local.priority == 50
	assert pairs[2].local.priority == 10
}

fn test_pairable_rejects_mismatched_candidates() {
	v4 := Candidate{
		address: netaddr.SocketAddr.parse('1.2.3.4:1')!
	}
	v6 := Candidate{
		address: netaddr.SocketAddr.parse('[2001:db8::1]:1')!
	}
	// Pairing across address families produces checks that cannot succeed.
	assert !pairable(v4, v6)
	assert pairable(v4, v4)

	other_component := Candidate{
		component: 2
		address:   netaddr.SocketAddr.parse('1.2.3.4:1')!
	}
	assert !pairable(v4, other_component)

	tcp := Candidate{
		transport: .tcp
		address:   netaddr.SocketAddr.parse('1.2.3.4:1')!
	}
	assert !pairable(v4, tcp)

	link_local := Candidate{
		address: netaddr.SocketAddr.parse('169.254.1.1:1')!
	}
	assert !pairable(v4, link_local)
	assert pairable(link_local, link_local)
}

fn test_interface_filter() {
	loopback := netaddr.IpAddr.parse('127.0.0.1')!
	link_local := netaddr.IpAddr.parse('169.254.1.1')!
	global := netaddr.IpAddr.parse('8.8.8.8')!
	v6 := netaddr.IpAddr.parse('2001:db8::1')!
	mapped := netaddr.IpAddr.parse('::ffff:1.2.3.4')!

	assert is_candidate_address(global, InterfaceOptions{})
	assert !is_candidate_address(loopback, InterfaceOptions{})
	assert is_candidate_address(loopback, InterfaceOptions{ include_loopback: true })
	assert !is_candidate_address(link_local, InterfaceOptions{})
	assert is_candidate_address(link_local, InterfaceOptions{ include_link_local: true })
	assert !is_candidate_address(v6, InterfaceOptions{ include_ipv6: false })
	assert !is_candidate_address(global, InterfaceOptions{ include_ipv4: false })
	// An IPv4-mapped address duplicates a candidate gathered separately and
	// cannot be paired with anything.
	assert !is_candidate_address(mapped, InterfaceOptions{})
	assert !is_candidate_address(netaddr.IpAddr{}, InterfaceOptions{})
}

fn test_local_interface_enumeration_finds_loopback() {
	addresses := local_interface_addresses(include_loopback: true)!
	assert addresses.len > 0, 'no local addresses found'
	assert addresses.any(it.is_loopback()), 'loopback was requested but not returned'

	// Without the option, loopback must not appear.
	routable := local_interface_addresses()!
	assert !routable.any(it.is_loopback())
}

fn test_agent_generates_strong_credentials() {
	mut agent := Agent.new()!
	defer {
		agent.close()
	}
	ufrag, pwd := agent.local_credentials()
	// RFC 8445 section 5.2.1 requires 24 bits in the fragment and 128 in the
	// password.
	assert ufrag.len >= 4
	assert pwd.len >= 22
	assert agent.state() == .new
}

fn test_agent_rejects_weak_credentials() {
	Agent.new(local_ufrag: 'ab', local_pwd: 'a-perfectly-long-password') or { return }
	assert false, 'a short ufrag must be rejected'
}