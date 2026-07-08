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

fn test_agent_rejects_short_password() {
	// The password is the only secret protecting connectivity checks.
	if _ := Agent.new(local_ufrag: 'abcd', local_pwd: 'tooshort') {
		assert false, 'a short password must be rejected'
	} else {
		assert err is AgentError
	}
}

fn test_set_remote_credentials_validates() {
	mut agent := Agent.new()!
	defer {
		agent.close()
	}
	agent.set_remote_credentials('ab', 'x') or {
		agent.set_remote_credentials('abcd', 'a-password-long-enough-for-ice')!
		return
	}
	assert false, 'weak remote credentials must be rejected'
}

fn test_add_remote_candidate_requires_valid_input() {
	mut agent := Agent.new()!
	defer {
		agent.close()
	}
	agent.add_remote_candidate_string('nonsense') or {
		agent.add_remote_candidate_string('1 1 udp 100 1.2.3.4 5000 typ host')!
		assert agent.statistics().remote_candidates == 1
		// A duplicate is ignored rather than doubling the check list.
		agent.add_remote_candidate_string('1 1 udp 100 1.2.3.4 5000 typ host')!
		assert agent.statistics().remote_candidates == 1
		return
	}
	assert false, 'a malformed candidate must be rejected'
}

fn test_remote_candidate_count_is_bounded() {
	mut agent := Agent.new()!
	defer {
		agent.close()
	}
	for i in 0 .. max_remote_candidates {
		agent.add_remote_candidate_string('${i} 1 udp 100 1.2.3.${1 + i % 200} 5000 typ host') or {
			break
		}
	}
	agent.add_remote_candidate_string('x 1 udp 100 9.9.9.9 5000 typ host') or {
		assert err is AgentError
		return
	}
	assert false, 'an unbounded remote candidate list must be refused'
}

// connect_pair drives two agents through a signalling exchange over loopback
// and returns once both report connectivity.
fn connect_pair(timeout time.Duration) !(&Agent, &Agent) {
	options := InterfaceOptions{
		include_loopback: true
	}
	mut controlling := Agent.new(
		role:           .controlling
		interfaces:     options
		check_interval: 10 * time.millisecond
	)!
	mut controlled := Agent.new(
		role:           .controlled
		interfaces:     options
		check_interval: 10 * time.millisecond
	)!

	a_ufrag, a_pwd := controlling.local_credentials()
	b_ufrag, b_pwd := controlled.local_credentials()
	controlling.set_remote_credentials(b_ufrag, b_pwd)!
	controlled.set_remote_credentials(a_ufrag, a_pwd)!

	controlling.gather()!
	controlled.gather()!

	for candidate in controlling.local_candidates() {
		controlled.add_remote_candidate(candidate)!
	}
	for candidate in controlled.local_candidates() {
		controlling.add_remote_candidate(candidate)!
	}

	controlling.connect(timeout)!
	controlled.connect(timeout)!
	return controlling, controlled
}

fn test_two_agents_connect_over_loopback() {
	mut controlling, mut controlled := connect_pair(10 * time.second)!
	defer {
		controlling.close()
		controlled.close()
	}

	assert controlling.state() in [ConnectionState.connected, .completed]
	assert controlled.state() in [ConnectionState.connected, .completed]

	pair := controlling.selected_pair()?
	assert pair.state == .succeeded
	// Both agents run in this process, so the winning pair is on one of the
	// local interfaces - which one depends on their relative priority, and
	// loopback does not necessarily win.
	assert pair.local.address.family() == pair.remote.address.family()

	stats := controlling.statistics()
	assert stats.succeeded_pairs >= 1
	assert stats.local_candidates >= 1
	assert stats.remote_candidates >= 1
}

fn test_connected_agents_exchange_data() {
	mut controlling, mut controlled := connect_pair(10 * time.second)!
	defer {
		controlling.close()
		controlled.close()
	}

	payload := 'hello over ICE'.bytes()
	controlling.send(payload)!
	received := controlled.recv(5 * time.second)!
	assert received == payload

	reply := 'and back again'.bytes()
	controlled.send(reply)!
	assert controlling.recv(5 * time.second)! == reply
}

fn test_agents_reach_completed_after_nomination() {
	mut controlling, mut controlled := connect_pair(10 * time.second)!
	defer {
		controlling.close()
		controlled.close()
	}

	// The controlling agent nominates once a pair succeeds; both sides should
	// settle on completed shortly afterwards.
	deadline := time.now().add(5 * time.second)
	for time.now() < deadline {
		if controlling.state() == .completed && controlled.state() == .completed {
			break
		}
		time.sleep(20 * time.millisecond)
	}
	assert controlling.state() == .completed, 'controlling stayed ${controlling.state()}'
	assert controlled.state() == .completed, 'controlled stayed ${controlled.state()}'

	pair := controlling.selected_pair()?
	assert pair.nominated
}

fn test_agent_fails_when_no_pair_can_connect() {
	mut agent := Agent.new(
		role:                 .controlling
		interfaces:           InterfaceOptions{
			include_loopback: true
		}
		check_interval:       5 * time.millisecond
		binding_timeout:      20 * time.millisecond
		max_binding_requests: 2
	)!
	defer {
		agent.close()
	}
	agent.set_remote_credentials('abcd', 'a-password-long-enough-for-ice')!
	agent.gather()!
	// 192.0.2.0/24 is TEST-NET-1: reserved for documentation and guaranteed
	// not to be routable, so the check can only ever time out.
	agent.add_remote_candidate_string('1 1 udp 100 192.0.2.1 9 typ host')!

	agent.connect(3 * time.second) or {
		assert err is AgentError
		return
	}
	assert false, 'an unreachable peer must not report a connection'
}

fn test_send_before_connect_is_refused() {
	mut agent := Agent.new()!
	defer {
		agent.close()
	}
	agent.send('x'.bytes()) or {
		assert err is AgentError
		if err is AgentError {
			assert err.reason == .wrong_state
		}
		return
	}
	assert false, 'sending without a selected pair must fail'
}

fn test_operations_after_close_are_refused() {
	mut agent := Agent.new()!
	agent.close()
	agent.close()

	assert agent.state() == .closed
	agent.send('x'.bytes()) or {
		agent.add_remote_candidate_string('1 1 udp 100 1.2.3.4 5000 typ host') or {
			agent.set_remote_credentials('abcd', 'a-password-long-enough-for-ice') or { return }
			assert false, 'setting credentials after close must fail'
		}
		assert false, 'adding a candidate after close must fail'
	}
	assert false, 'sending after close must fail'
}

fn test_recv_times_out_without_data() {
	mut agent := Agent.new()!
	defer {
		agent.close()
	}
	started := time.now()
	agent.recv(50 * time.millisecond) or {
		assert err is AgentError
		assert time.now() - started >= 40 * time.millisecond
		return
	}
	assert false, 'recv must time out when nothing arrives'
}

fn test_nominated_pair_wins_over_a_higher_priority_one() {
	// A controlled agent may already have selected a higher-priority pair when
	// the controlling agent's nomination lands on a different one. The
	// nomination has to win: the two ends must agree on where traffic goes, and
	// priority is only the tiebreak used until one of them decides.
	mut agent := Agent.new(role: .controlled)!
	defer {
		agent.close()
	}
	agent.set_remote_credentials('abcd', 'a-password-long-enough-for-ice')!

	agent.mu.lock()
	agent.pairs = [
		CandidatePair{
			local:  Candidate{
				priority: 1000
				address:  netaddr.SocketAddr.parse('1.1.1.1:1')!
			}
			remote: Candidate{
				priority: 1000
				address:  netaddr.SocketAddr.parse('2.2.2.2:2')!
			}
			state:  .succeeded
		},
		CandidatePair{
			local:     Candidate{
				priority: 10
				address:  netaddr.SocketAddr.parse('3.3.3.3:3')!
			}
			remote:    Candidate{
				priority: 10
				address:  netaddr.SocketAddr.parse('4.4.4.4:4')!
			}
			state:     .succeeded
			nominated: true
		},
	]
	agent.selected = 0
	agent.consider_selection(1)
	selected := agent.selected
	state := agent.state
	agent.mu.unlock()

	assert selected == 1, 'the nominated pair must be selected even though it ranks lower'
	assert state == .completed
}

fn test_the_no_host_policy_discloses_no_local_addresses() {
	// The sockets still have to be bound - a candidate the peer never sees is
	// still where our traffic comes from - but nothing may be signalled.
	mut agent := Agent.new(
		interfaces:    InterfaceOptions{
			include_loopback: true
		}
		gather_policy: .no_host
	)!
	defer {
		agent.close()
	}

	agent.gather() or {
		assert err is AgentError
		if err is AgentError {
			assert err.reason == .no_candidates
		}
		assert agent.local_candidates().len == 0
		return
	}
	assert false, 'with no STUN server the no-host policy has nothing to gather'
}

fn test_the_relay_only_policy_refuses_rather_than_leaking() {
	mut agent := Agent.new(
		interfaces:    InterfaceOptions{
			include_loopback: true
		}
		gather_policy: .relay_only
	)!
	defer {
		agent.close()
	}

	agent.gather() or {
		assert err.msg().contains('TURN')
		assert agent.local_candidates().len == 0
		return
	}
	assert false, 'relay-only must not fall back to gathering host candidates'
}

fn test_the_default_policy_gathers_host_candidates() {
	mut agent := Agent.new(
		interfaces: InterfaceOptions{
			include_loopback: true
		}
	)!
	defer {
		agent.close()
	}
	agent.gather()!
	assert agent.local_candidates().len > 0
	assert GatherPolicy.all.str() == 'all'
	assert GatherPolicy.no_host.str() == 'no-host'
}

fn test_an_mdns_candidate_is_parsed_rather_than_refused() {
	// RFC 8828: a browser signals a random ".local" name instead of its private
	// addresses. Refusing it would throw away every local-network path.
	candidate :=
		parse_candidate('candidate:1 1 udp 2130706431 d4f4c2b0-1111-4000-8000-000000000000.local 44444 typ host')!
	assert candidate.needs_resolution()
	assert candidate.hostname == 'd4f4c2b0-1111-4000-8000-000000000000.local'
	assert candidate.address.port == 44444
	assert candidate.typ == .host
}

fn test_an_mdns_candidate_serialises_back_to_its_name() {
	line := 'candidate:1 1 udp 2130706431 abc.local 44444 typ host'
	candidate := parse_candidate(line)!
	assert 'candidate:${candidate}' == line
}

fn test_a_host_that_is_neither_an_address_nor_local_is_refused() {
	// Anything else would be a name this stack has no way to resolve, and
	// accepting it would mean a candidate that can never be used.
	for host in ['example.com', 'localhost', 'not an address', '999.999.999.999'] {
		if _ := parse_candidate('candidate:1 1 udp 2130706431 ${host} 44444 typ host') {
			assert false, '"${host}" is not usable as a candidate address'
		}
	}
}