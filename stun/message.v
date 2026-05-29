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

// MessageType.from_value unpacks a wire type. Unknown methods are preserved as
// their numeric value so that an unsupported request can still be answered with
// the correct method in the error response.
pub fn MessageType.from_value(v u16) MessageType {
	method := (v & 0x000F) | ((v & 0x00E0) >> 1) | ((v & 0x3E00) >> 2)
	class := ((v & 0x0010) >> 4) | ((v & 0x0100) >> 7)
	return MessageType{
		method: unsafe { Method(method) }
		class:  unsafe { Class(u8(class)) }
	}
}

pub fn (t MessageType) str() string {
	return '${t.method} ${t.class}'
}

// IntegrityAlgorithm selects which MESSAGE-INTEGRITY variant to append.
// ICE (RFC 8445) uses the HMAC-SHA1 form; RFC 8489 added the SHA-256 form for
// long-term credentials.
pub enum IntegrityAlgorithm {
	sha1
	sha256
}

// EncodeOptions controls the authentication attributes appended during
// encoding. Both are appended after every other attribute and in the order the
// RFC requires: MESSAGE-INTEGRITY first, FINGERPRINT last.
@[params]
pub struct EncodeOptions {
pub:
	// integrity_key, when non-empty, causes a MESSAGE-INTEGRITY attribute to be
	// computed over the message and appended.
	integrity_key []u8
	// integrity_algorithm selects the HMAC used with integrity_key.
	integrity_algorithm IntegrityAlgorithm = .sha1
	// fingerprint appends a FINGERPRINT attribute. RFC 8445 requires it on all
	// ICE connectivity checks.
	fingerprint bool
}

// DecodeOptions bounds the resources a single decode may consume. The defaults
// are sized for WebRTC; a TURN relay forwarding large DATA indications can
// raise max_message_size.
@[params]
pub struct DecodeOptions {
pub:
	max_message_size int = default_max_message_size
	max_attributes   int = default_max_attributes
}

// Message is a decoded STUN message.
//
// raw holds the exact bytes the message was decoded from, or the bytes produced
// by the most recent encode. Integrity checks are defined over the encoded form
// - MESSAGE-INTEGRITY covers everything before itself - so they can only be
// verified against raw, never against a re-encoding, which might order
// attributes differently than the sender did.
pub struct Message {
pub mut:
	typ            MessageType
	transaction_id [transaction_id_size]u8
	attributes     []RawAttribute
	raw            []u8
}

// Message.new returns a message with a fresh random transaction identifier.
//
// The identifier is 96 bits from the system CSPRNG. It is not merely a
// correlation token: for a client behind a NAT it is the only thing an off-path
// attacker would have to guess in order to forge a response, so it must not
// come from a predictable source.
pub fn Message.new(class Class, method Method) !Message {
	tid := randutil.bytes(transaction_id_size)!
	mut id := [transaction_id_size]u8{}
	for i in 0 .. transaction_id_size {
		id[i] = tid[i]
	}
	return Message{
		typ:            MessageType{
			method: method
			class:  class
		}
		transaction_id: id
	}
}