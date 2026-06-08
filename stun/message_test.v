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