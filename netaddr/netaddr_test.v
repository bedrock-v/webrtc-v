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