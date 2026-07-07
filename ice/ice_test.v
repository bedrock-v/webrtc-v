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