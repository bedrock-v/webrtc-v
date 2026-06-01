module stun

import crypto.hmac
import crypto.sha1
import crypto.sha256
import hash.crc32
import webrtc.internal.codec
import webrtc.internal.randutil

// magic_cookie is the fixed value in bytes 4..8 of every STUN message
// (RFC 8489 section 5). It is what lets a receiver tell STUN apart from other
// protocols multiplexed on the same socket.
pub const magic_cookie = u32(0x2112A442)

// header_size is the size of the fixed STUN header.
pub const header_size = 20

// transaction_id_size is the length of the transaction identifier.
pub const transaction_id_size = 12

// fingerprint_xor is XORed into the CRC-32 in a FINGERPRINT attribute
// (RFC 8489 section 14.7), so that a plain CRC never appears on the wire.
pub const fingerprint_xor = u32(0x5354554e)

// default_max_message_size bounds how much memory one message may consume.
// The length field is 16 bits, but nothing in WebRTC needs anywhere near that,
// and a lower ceiling limits what a single spoofed datagram can cost us.
pub const default_max_message_size = 8192

// default_max_attributes bounds the attribute count. A message that packs the
// maximum body with 4-byte attributes would otherwise force thousands of small
// allocations.
pub const default_max_attributes = 128

// Class is the two-bit STUN message class.
pub enum Class as u8 {
	request          = 0x00
	indication       = 0x01
	success_response = 0x02
	error_response   = 0x03
}

pub fn (c Class) str() string {
	return match c {
		.request { 'request' }
		.indication { 'indication' }
		.success_response { 'success response' }
		.error_response { 'error response' }
	}
}

// Method is the twelve-bit STUN method. Binding is the only method WebRTC needs
// directly; the TURN methods are here because a relay candidate speaks them
// over the same codec.
pub enum Method as u16 {
	binding            = 0x001
	allocate           = 0x003
	refresh            = 0x004
	send               = 0x006
	data               = 0x007
	create_permission  = 0x008
	channel_bind       = 0x009
	connect            = 0x00A
	connection_bind    = 0x00B
	connection_attempt = 0x00C
}

// MessageType is the class and method pair carried in the first two bytes.
pub struct MessageType {
pub:
	method Method = .binding
	class  Class  = .request
}

// value packs the type into its wire representation. The method bits are split
// around the class bits (RFC 5389 section 6), which is why this is not a plain
// bit concatenation.
pub fn (t MessageType) value() u16 {
	m := u16(t.method)
	c := u16(t.class)
	return (m & 0x000F) | ((m & 0x0070) << 1) | ((m & 0x0F80) << 2) | ((c & 0x0001) << 4) | ((c & 0x0002) << 7)
}