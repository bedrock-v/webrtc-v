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

fn test_ipv6_parse_and_format_round_trip() {
	cases := {
		'::':                                      '::'
		'::1':                                     '::1'
		'1::':                                     '1::'
		'1::2':                                    '1::2'
		'2001:db8::1':                             '2001:db8::1'
		'2001:0db8:0000:0000:0000:0000:0000:0001': '2001:db8::1'
		'1:2:3:4:5:6:7:8':                         '1:2:3:4:5:6:7:8'
		'fe80::1':                                 'fe80::1'
		'2001:DB8::AB':                            '2001:db8::ab'
		'::ffff:1.2.3.4':                          '::ffff:1.2.3.4'
		'2001:db8:0:0:1:0:0:1':                    '2001:db8::1:0:0:1'
	}
	for input, want in cases {
		addr := IpAddr.parse(input)!
		assert addr.family == .ipv6
		assert addr.octets.len == 16
		assert addr.str() == want, 'parse(${input}).str() = ${addr.str()}, want ${want}'
	}
}

fn test_ipv6_single_zero_group_is_not_compressed() {
	// RFC 5952 section 4.2.2: '::' must not replace a single group.
	addr := IpAddr.parse('1:2:3:4:5:6:0:8')!
	assert addr.str() == '1:2:3:4:5:6:0:8'
}

fn test_ipv6_leftmost_run_wins_on_tie() {
	// RFC 5952 section 4.2.3: with equal-length runs, compress the first.
	addr := IpAddr.parse('1:0:0:2:3:0:0:4')!
	assert addr.str() == '1::2:3:0:0:4'
}

fn test_ipv6_rejects_malformed() {
	bad := ['', ':', ':1', '1:', '1:::2', '::1::2', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', '12345::',
		'gggg::1', '1:2:3:4:5:6:7:8:', '::1.2.3', '1.2.3.4:5:6']
	for c in bad {
		if _ := IpAddr.parse(c) {
			assert false, 'expected ${c} to be rejected'
		}
	}
}

fn test_ipv6_embedded_ipv4() {
	mapped := IpAddr.parse('::ffff:192.168.1.1')!
	assert mapped.is_ipv4_mapped()
	assert mapped.octets[12..] == [u8(192), 168, 1, 1]
	assert mapped.str() == '::ffff:192.168.1.1'

	unmapped := mapped.unmap()
	assert unmapped.family == .ipv4
	assert unmapped.str() == '192.168.1.1'

	// A non-mapped address passes through unchanged.
	plain := IpAddr.parse('2001:db8::1')!
	assert plain.unmap().equal(plain)
}