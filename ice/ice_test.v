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