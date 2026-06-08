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

// Section 2.2: sample IPv4 success response.
const vector_response_v4 = '0101003c2112a442b7e7a701bc34d686fa87dfae' + '8022000b' +
	'74657374207665' + '63746f7220' + '00200008' + '0001a147e112a643' + '00080014' +
	'2b91f599fd9e90c38c7489f92af9ba53f06be7d7' + '80280004' + 'c07d4c96'

// Section 2.3: sample IPv6 success response.
const vector_response_v6 = '010100482112a442b7e7a701bc34d686fa87dfae' + '8022000b' +
	'74657374207665' + '63746f7220' + '00200014' +
	'0002a14701 13a9faa5d3f179bc25f4b5bed2b9d9'.replace(' ', '') + '00080014' +
	'a38295 4e4be67bf11784c97c8292c275bfe3ed41'.replace(' ', '') + '80280004' + 'c8fb0b4c'

const vector_response_password = 'VOkJxbRl1RmTxUk/WvJxBt'
const vector_response_software = 'test vector'

// RFC 5769 predates RFC 8489 and pads attribute values with spaces. RFC 8489
// section 14 requires the padding to be zero on send, which is what this
// implementation emits. The digests cover the padding, so a re-encoded message
// cannot be byte-identical to the reference and the comparison is split in two:
// the bytes up to MESSAGE-INTEGRITY must match once padding is normalised, and
// the digests must then verify against the same password.
fn zero_attribute_padding(raw []u8) ![]u8 {
	mut out := raw.clone()
	mut pos := header_size
	for pos + 4 <= out.len {
		value_len := int((u16(out[pos + 2]) << 8) | u16(out[pos + 3]))
		pad := padded_size(value_len) - value_len
		start := pos + 4 + value_len
		if start + pad > out.len {
			return error('attribute at ${pos} runs past the message')
		}
		for i in 0 .. pad {
			out[start + i] = 0
		}
		pos = start + pad
	}
	return out
}