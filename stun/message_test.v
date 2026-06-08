module stun

import encoding.hex
import webrtc.netaddr

// V compiles each _test.v file on its own, so this file carries its own copy of
// the RFC 5769 section 2.1 request rather than sharing one with rfc5769_test.v.
const sample_request = '000100582112a442b7e7a701bc34d686fa87dfae' + '80220010' +
	'5354554e2074657374' + '20636c69656e74' + '00240004' + '6e0001ff' + '80290008' +
	'932ff9b151263b36' + '00060009' + '6576746a3a68367659202020' + '00080014' +
	'9aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2' + '80280004' + 'e57a3bcf'

fn test_message_type_round_trip_over_all_classes_and_methods() {
	methods := [Method.binding, .allocate, .refresh, .send, .data, .create_permission, .channel_bind,
		.connect, .connection_bind, .connection_attempt]
	classes := [Class.request, .indication, .success_response, .error_response]

	for method in methods {
		for class in classes {
			typ := MessageType{
				method: method
				class:  class
			}
			back := MessageType.from_value(typ.value())
			assert back.method == method
			assert back.class == class
			// The top two bits must stay clear so STUN is distinguishable from
			// the other protocols sharing the port.
			assert typ.value() & 0xC000 == 0
		}
	}
}

fn test_message_type_known_wire_values() {
	// Values a WebRTC endpoint sees on the wire, from RFC 8489 section 5.
	assert MessageType{
		method: .binding
		class:  .request
	}.value() == 0x0001
	assert MessageType{
		method: .binding
		class:  .indication
	}.value() == 0x0011
	assert MessageType{
		method: .binding
		class:  .success_response
	}.value() == 0x0101
	assert MessageType{
		method: .binding
		class:  .error_response
	}.value() == 0x0111
	assert MessageType{
		method: .allocate
		class:  .request
	}.value() == 0x0003
	assert MessageType{
		method: .allocate
		class:  .error_response
	}.value() == 0x0113
}

fn test_message_type_preserves_unknown_methods() {
	// A server must be able to answer an unsupported method with an error
	// response that names the same method, so unknown values round-trip.
	typ := MessageType.from_value(0x0FFF)
	assert typ.value() == 0x0FFF
}

fn test_is_message_demultiplexing() {
	valid := hex.decode(sample_request)!
	assert is_message(valid)

	// Too short for a header.
	assert !is_message(valid[..19])

	// RFC 7983 assigns first-byte ranges to each protocol on the port. A DTLS
	// handshake record starts with 22, which has the same top two bits as STUN,
	// so a check that only masks those bits would misroute it.
	for first, name in {
		u8(0x14): 'DTLS change_cipher_spec'
		u8(0x16): 'DTLS handshake'
		u8(0x17): 'DTLS application_data'
		u8(0x40): 'TURN channel'
		u8(0x80): 'RTP'
		u8(0xC8): 'RTCP sender report'
	} {
		mut other := valid.clone()
		other[0] = first
		assert !is_message(other), '${name} must not be classified as STUN'
	}

	// Right leading byte, wrong cookie.
	mut no_cookie := valid.clone()
	no_cookie[4] = 0x00
	assert !is_message(no_cookie)
	assert !is_message([]u8{})
}

fn test_decode_rejects_short_and_malformed_headers() {
	cases := {
		'empty':                    ''
		'partial header':           '000100002112a442b7e7a701bc34d6'
		'no magic cookie':          '0001000000000000b7e7a701bc34d686fa87dfae'
		'leading bits set':         '4001000021 12a442b7e7a701bc34d686fa87dfae'.replace(' ', '')
		'length not multiple of 4': '000100022112a442b7e7a701bc34d686fa87dfae0000'
		'length longer than data':  '000100202112a442b7e7a701bc34d686fa87dfae'
		'length shorter than data': '000100002112a442b7e7a701bc34d686fa87dfae00060004deadbeef'
	}
	for name, encoded in cases {
		raw := hex.decode(encoded)!
		if _ := Message.decode(raw) {
			assert false, 'expected ${name} to be rejected'
		} else {
			assert err is DecodeError, '${name} produced ${err}'
		}
	}
}

fn test_decode_rejects_attribute_running_past_end() {
	// Header declares a 8-byte body; the attribute inside declares 32 bytes.
	raw := hex.decode('000100082112a442b7e7a701bc34d686fa87dfae00060020deadbeef')!
	Message.decode(raw) or {
		assert err is DecodeError
		if err is DecodeError {
			assert err.reason == .bad_length || err.reason == .bad_attribute
		}
		return
	}
	assert false, 'attribute overrunning the body must be rejected'
}

fn test_decode_enforces_size_limit() {
	mut msg := Message.new(.request, .binding)!
	msg.add(attr_data, []u8{len: 1000})
	raw := msg.encode()!

	Message.decode(raw, max_message_size: 256) or {
		assert err is DecodeError
		if err is DecodeError {
			assert err.reason == .too_large
		}
		// The same bytes decode fine under the default limit.
		Message.decode(raw)!
		return
	}
	assert false, 'oversized message must be rejected'
}

fn test_decode_enforces_attribute_limit() {
	mut msg := Message.new(.request, .binding)!
	for i in 0 .. 40 {
		msg.add(attr_padding, [u8(i), 0, 0, 0])
	}
	raw := msg.encode()!

	Message.decode(raw, max_attributes: 10) or {
		assert err is DecodeError
		if err is DecodeError {
			assert err.reason == .too_many_attributes
		}
		return
	}
	assert false, 'attribute flood must be rejected'
}

fn test_zero_length_attribute_round_trips() {
	// USE-CANDIDATE is a flag: present with no value.
	mut msg := Message.new(.request, .binding)!
	msg.add_use_candidate()
	raw := msg.encode()!

	decoded := Message.decode(raw)!
	assert decoded.has_use_candidate()
	attr := decoded.get(attr_use_candidate)?
	assert attr.value.len == 0
}

fn test_transaction_ids_are_unpredictable() {
	mut seen := map[string]bool{}
	for _ in 0 .. 128 {
		msg := Message.new(.request, .binding)!
		id := msg.transaction_id[..].hex()
		assert id !in seen, 'transaction id repeated'
		seen[id] = true
	}
}

fn test_response_copies_transaction_id_and_method() {
	req := Message.new(.request, .allocate)!
	resp := Message.response(req, .error_response)
	assert resp.transaction_id == req.transaction_id
	assert resp.typ.method == .allocate
	assert resp.typ.class == .error_response
}

fn test_get_and_get_all() {
	mut msg := Message.new(.request, .binding)!
	msg.add(attr_xor_peer_address, [u8(1)])
	msg.add(attr_xor_peer_address, [u8(2)])
	msg.add(attr_priority, [u8(0), 0, 0, 1])

	first := msg.get(attr_xor_peer_address)?
	assert first.value == [u8(1)]
	assert msg.get_all(attr_xor_peer_address).len == 2
	assert msg.get_all(attr_lifetime).len == 0
	assert msg.has(attr_priority)
	assert !msg.has(attr_realm)
	assert msg.get(attr_realm) == none
}

fn test_encode_rejects_caller_supplied_digests() {
	// Accepting a caller-supplied MESSAGE-INTEGRITY would let a stale or forged
	// digest be transmitted as though the library had computed it.
	for typ in [attr_message_integrity, attr_message_integrity_sha256, attr_fingerprint] {
		mut msg := Message.new(.request, .binding)!
		msg.add(typ, []u8{len: 20})
		msg.encode() or {
			assert err is EncodeError
			continue
		}
		assert false, 'encoding ${attr_name(typ)} as a plain attribute must be rejected'
	}
}

fn test_integrity_sha256_round_trip() {
	key := 'a-long-term-key'.bytes()
	mut msg := Message.new(.request, .binding)!
	msg.add_username('user')!

	raw := msg.encode(integrity_key: key, integrity_algorithm: .sha256, fingerprint: true)!
	decoded := Message.decode(raw)!

	decoded.check_message_integrity_sha256(key)!
	decoded.check_fingerprint()!

	// The SHA-1 attribute is absent, and asking for it must say so rather than
	// silently succeeding.
	decoded.check_message_integrity(key) or {
		assert err is IntegrityError
		if err is IntegrityError {
			assert err.reason == .missing
		}
		return
	}
	assert false, 'missing MESSAGE-INTEGRITY must be reported'
}

fn test_integrity_rejects_appended_attribute() {
	// An attacker who appends an attribute after MESSAGE-INTEGRITY adds content
	// the digest does not cover. Ignoring it is not enough: the message must be
	// rejected.
	key := 'secret'.bytes()
	mut msg := Message.new(.request, .binding)!
	msg.add_username('user')!
	raw := msg.encode(integrity_key: key)!

	mut tampered := raw.clone()
	// Append a 4-byte PRIORITY attribute and grow the declared body length.
	tampered << [u8(0x00), 0x24, 0x00, 0x04, 0xff, 0xff, 0xff, 0xff]
	body := tampered.len - header_size
	tampered[2] = u8(body >> 8)
	tampered[3] = u8(body)

	decoded := Message.decode(tampered)!
	decoded.check_message_integrity(key) or {
		assert err is IntegrityError
		if err is IntegrityError {
			assert err.reason == .not_last
		}
		return
	}
	assert false, 'attribute appended after MESSAGE-INTEGRITY must be rejected'
}

fn test_integrity_allows_fingerprint_after_it() {
	key := 'secret'.bytes()
	mut msg := Message.new(.request, .binding)!
	raw := msg.encode(integrity_key: key, fingerprint: true)!
	decoded := Message.decode(raw)!
	decoded.check_message_integrity(key)!
	decoded.check_fingerprint()!
}

fn test_integrity_rejects_empty_key_and_wrong_length() {
	key := 'secret'.bytes()
	mut msg := Message.new(.request, .binding)!
	raw := msg.encode(integrity_key: key)!
	decoded := Message.decode(raw)!

	decoded.check_message_integrity([]u8{}) or {
		assert err is IntegrityError
		if err is IntegrityError {
			assert err.reason == .malformed
		}
		return
	}
	assert false, 'empty key must be rejected'
}

fn test_fingerprint_must_be_last() {
	mut msg := Message.new(.request, .binding)!
	raw := msg.encode(fingerprint: true)!

	mut tampered := raw.clone()
	tampered << [u8(0x00), 0x24, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01]
	body := tampered.len - header_size
	tampered[2] = u8(body >> 8)
	tampered[3] = u8(body)

	decoded := Message.decode(tampered)!
	decoded.check_fingerprint() or {
		assert err is IntegrityError
		if err is IntegrityError {
			assert err.reason == .not_last
		}
		return
	}
	assert false, 'FINGERPRINT must be the final attribute'
}

fn test_missing_fingerprint_is_reported() {
	mut msg := Message.new(.request, .binding)!
	raw := msg.encode()!
	decoded := Message.decode(raw)!
	decoded.check_fingerprint() or {
		assert err is IntegrityError
		return
	}
	assert false, 'missing FINGERPRINT must be reported'
}

fn test_unknown_comprehension_required_detection() {
	mut msg := Message.new(.request, .binding)!
	msg.add_username('u')!
	msg.add(0x7FFF, [u8(1), 2, 3, 4]) // comprehension-required, unknown
	msg.add(0x8FFF, [u8(1), 2, 3, 4]) // comprehension-optional, unknown
	msg.add(0x7FFF, [u8(5), 6, 7, 8]) // duplicate: reported once

	unknown := msg.unknown_comprehension_required([attr_username])
	assert unknown == [u16(0x7FFF)]
	assert is_comprehension_required(0x7FFF)
	assert !is_comprehension_required(0x8000)
}

fn test_attribute_names() {
	assert attr_name(attr_xor_mapped_address) == 'XOR-MAPPED-ADDRESS'
	assert attr_name(attr_ice_controlling) == 'ICE-CONTROLLING'
	assert attr_name(0x9999) == '0x9999'
}

fn test_encode_rejects_oversized_attribute() {
	mut msg := Message.new(.request, .binding)!
	msg.add(attr_data, []u8{len: 0x10000})
	msg.encode() or {
		assert err is EncodeError
		return
	}
	assert false, 'attribute larger than the length field must be rejected'
}