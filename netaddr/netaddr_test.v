module netaddr

fn test_ipv4_parse_and_format() {
	cases := ['0.0.0.0', '127.0.0.1', '192.168.1.1', '255.255.255.255', '8.8.8.8']
	for c in cases {
		addr := IpAddr.parse(c)!
		assert addr.family == .ipv4
		assert addr.octets.len == 4
		assert addr.str() == c
	}
}

fn test_ipv4_rejects_malformed() {
	bad := ['', '1.2.3', '1.2.3.4.5', '256.1.1.1', '1.2.3.-1', 'a.b.c.d', '1..2.3', '01.2.3.4',
		'1.2.3.04', '1.2.3.4 ']
	for c in bad {
		if _ := IpAddr.parse(c) {
			assert false, 'expected ${c} to be rejected'
		}
	}
}

fn test_ipv4_leading_zero_is_rejected() {
	// "010.1.1.1" is 8.1.1.1 to an octal-aware resolver and 10.1.1.1 to a
	// reader. Accepting it invites address-confusion bugs.
	IpAddr.parse('010.1.1.1') or { return }
	assert false, 'leading zeros must be rejected'
}