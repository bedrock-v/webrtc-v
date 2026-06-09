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

// assert_matches_reference checks a freshly encoded message against a reference
// from the RFC: identical bytes up to MESSAGE-INTEGRITY, then both digests
// verifying under the published password.
fn assert_matches_reference(encoded []u8, reference []u8, password string) ! {
	mine := Message.decode(encoded)!
	theirs := Message.decode(reference)!

	mi := mine.get(attr_message_integrity) or { return error('encoded message has no integrity') }
	ref_mi := theirs.get(attr_message_integrity) or {
		return error('reference message has no integrity')
	}
	assert mi.offset == ref_mi.offset, 'MESSAGE-INTEGRITY landed at a different offset'

	mine_prefix := zero_attribute_padding(encoded)![..mi.offset]
	ref_prefix := zero_attribute_padding(reference)![..ref_mi.offset]
	assert mine_prefix.hex() == ref_prefix.hex()

	key := short_term_key(password)!
	mine.check_message_integrity(key)!
	mine.check_fingerprint()!
	assert encoded.len == reference.len
}

fn test_rfc5769_request_decodes() {
	raw := hex.decode(vector_request)!
	msg := Message.decode(raw)!

	assert msg.typ.class == .request
	assert msg.typ.method == .binding
	assert msg.transaction_id[..].hex() == 'b7e7a701bc34d686fa87dfae'
	assert msg.software()! == vector_request_software
	assert msg.priority()! == 0x6e0001ff
	assert msg.ice_controlled()! == 0x932ff9b151263b36
	assert msg.username()! == vector_request_username
}

fn test_rfc5769_request_integrity_and_fingerprint() {
	raw := hex.decode(vector_request)!
	msg := Message.decode(raw)!

	key := short_term_key(vector_request_password)!
	msg.check_message_integrity(key)!
	msg.check_fingerprint()!
}

fn test_rfc5769_request_integrity_rejects_wrong_password() {
	raw := hex.decode(vector_request)!
	msg := Message.decode(raw)!

	key := short_term_key('not the password')!
	msg.check_message_integrity(key) or {
		assert err is IntegrityError
		if err is IntegrityError {
			assert err.reason == .mismatch
		}
		return
	}
	assert false, 'integrity must fail with the wrong key'
}

fn test_rfc5769_request_reencodes() {
	raw := hex.decode(vector_request)!
	decoded := Message.decode(raw)!

	// Rebuild the message from its semantic content and confirm the encoder
	// reproduces the reference layout.
	mut rebuilt := Message.with_transaction_id(.request, .binding, decoded.transaction_id)
	rebuilt.add_software(vector_request_software)!
	rebuilt.add_priority(0x6e0001ff)
	rebuilt.add_ice_controlled(0x932ff9b151263b36)
	rebuilt.add_username(vector_request_username)!

	out := rebuilt.encode(
		integrity_key: short_term_key(vector_request_password)!
		fingerprint:   true
	)!
	assert_matches_reference(out, raw, vector_request_password)!
}

fn test_rfc5769_ipv4_response() {
	raw := hex.decode(vector_response_v4)!
	msg := Message.decode(raw)!

	assert msg.typ.class == .success_response
	assert msg.typ.method == .binding
	assert msg.software()! == vector_response_software

	addr := msg.xor_mapped_address()!
	assert addr.ip.family == .ipv4
	assert addr.str() == '192.0.2.1:32853'

	msg.check_message_integrity(short_term_key(vector_response_password)!)!
	msg.check_fingerprint()!
}

fn test_rfc5769_ipv6_response() {
	raw := hex.decode(vector_response_v6)!
	msg := Message.decode(raw)!

	assert msg.typ.class == .success_response
	addr := msg.xor_mapped_address()!
	assert addr.ip.family == .ipv6
	assert addr.str() == '[2001:db8:1234:5678:11:2233:4455:6677]:32853'

	msg.check_message_integrity(short_term_key(vector_response_password)!)!
	msg.check_fingerprint()!
}