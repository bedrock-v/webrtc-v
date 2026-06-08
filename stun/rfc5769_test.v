module stun

import encoding.hex
import webrtc.netaddr

// The vectors in RFC 5769 are self-validating: each carries a MESSAGE-INTEGRITY
// computed with a published password and a FINGERPRINT over the whole message.
// Reproducing both from the decoded bytes exercises the header parser, the
// attribute walker, the length-field rewriting that both digests depend on, and
// the XOR-MAPPED-ADDRESS transform in one shot.

// Section 2.1: sample request from an ICE client.
const vector_request = '000100582112a442b7e7a701bc34d686fa87dfae' + '80220010' +
	'5354554e2074657374' + '20636c69656e74' + '00240004' + '6e0001ff' + '80290008' +
	'932ff9b151263b36' + '00060009' + '6576746a3a68367659202020' + '00080014' +
	'9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2' + '80280004' + 'e57a3bcf'

const vector_request_username = 'evtj:h6vY'
const vector_request_password = 'VOkJxbRl1RmTxUk/WvJxBt'
const vector_request_software = 'STUN test client'