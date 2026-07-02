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