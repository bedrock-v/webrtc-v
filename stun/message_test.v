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