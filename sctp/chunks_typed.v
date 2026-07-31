module sctp

import webrtc.internal.codec

// The typed chunk bodies a WebRTC association exchanges.

// Parameter type numbers from the IANA SCTP registry.
pub const param_heartbeat_info = u16(1)
pub const param_ipv4_address = u16(5)
pub const param_ipv6_address = u16(6)
pub const param_state_cookie = u16(7)
pub const param_unrecognized = u16(8)
pub const param_cookie_preservative = u16(9)
pub const param_host_name = u16(11)
pub const param_supported_address_types = u16(12)
pub const param_outgoing_ssn_reset = u16(13)
pub const param_incoming_ssn_reset = u16(14)
pub const param_reconfig_response = u16(16)
pub const param_random = u16(0x8002)
pub const param_chunk_list = u16(0x8003)
pub const param_hmac_algorithm = u16(0x8004)
pub const param_padding = u16(0x8005)
pub const param_supported_extensions = u16(0x8008)
pub const param_forward_tsn_supported = u16(0xC000)

// data_chunk_fixed_size is the DATA chunk's fixed fields, before the user data:
// the TSN, the stream identifier and sequence number, and the payload protocol
// identifier.
pub const data_chunk_fixed_size = 12

// DATA chunk flags. The bits are the low three of the flags byte
// (RFC 4960 section 3.3.1).
pub const data_flag_end = u8(0x01)
pub const data_flag_beginning = u8(0x02)
pub const data_flag_unordered = u8(0x04)
pub const data_flag_immediate_sack = u8(0x08)

// Payload protocol identifiers for data channels (RFC 8831 section 8).
//
// SCTP itself does not care what these mean; they are what tells a receiver
// whether a message is a string or binary, and whether it is a data channel
// control message rather than user data.
pub const ppid_dcep = u32(50)
pub const ppid_string = u32(51)
pub const ppid_binary_partial = u32(52)
pub const ppid_binary = u32(53)
pub const ppid_string_partial = u32(54)
pub const ppid_string_empty = u32(56)
pub const ppid_binary_empty = u32(57)

// Parameter is a type-length-value inside a chunk.
pub struct Parameter {
pub:
	typ   u16
	value []u8
}

fn marshal_parameters(parameters []Parameter) ![]u8 {
	mut w := codec.Writer.new()
	for parameter in parameters {
		total := 4 + parameter.value.len
		if total > 0xFFFF {
			return EncodeError{
				detail: 'parameter of ${total} bytes exceeds the 16-bit length field'
			}
		}
		w.u16(parameter.typ)
		w.u16(u16(total))
		w.bytes(parameter.value)
		w.pad(4)
	}
	return w.buf
}