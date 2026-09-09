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

// Message.with_transaction_id returns a message reusing a known identifier,
// which is how a response is built for a received request.
pub fn Message.with_transaction_id(class Class, method Method, tid [transaction_id_size]u8) Message {
	return Message{
		typ:            MessageType{
			method: method
			class:  class
		}
		transaction_id: tid
	}
}

// Message.response builds a response to req, copying its transaction id and
// method. This is the only correct way to answer a request, so it exists to
// keep callers from open-coding it and getting the method wrong.
pub fn Message.response(req &Message, class Class) Message {
	return Message{
		typ:            MessageType{
			method: req.typ.method
			class:  class
		}
		transaction_id: req.transaction_id
	}
}

// is_message reports whether a datagram plausibly holds a STUN message.
//
// This is the demultiplexing predicate from RFC 7983. On a WebRTC socket one
// port carries STUN, DTLS, RTP and RTCP, and they are told apart by the value
// of the first byte: 0-3 is STUN, 20-63 is DTLS, 128-191 is RTP or RTCP. Note
// that checking only that the top two bits are clear is not enough - a DTLS
// record begins with a content type of 20-25, which also has them clear - so
// the full range is tested here and the magic cookie confirms the guess.
//
// It is deliberately cheap and does not validate the body; Message.decode does
// that.
pub fn is_message(b []u8) bool {
	if b.len < header_size {
		return false
	}
	if b[0] > 3 {
		return false
	}
	cookie := (u32(b[4]) << 24) | (u32(b[5]) << 16) | (u32(b[6]) << 8) | u32(b[7])
	return cookie == magic_cookie
}

// add appends an attribute. Attributes are emitted in insertion order, which
// matters because MESSAGE-INTEGRITY and FINGERPRINT protect what precedes them.
pub fn (mut m Message) add(typ u16, value []u8) {
	m.attributes << RawAttribute{
		typ:   typ
		value: value
	}
}

// get returns the first attribute of the given type, or none.
pub fn (m &Message) get(typ u16) ?RawAttribute {
	for attr in m.attributes {
		if attr.typ == typ {
			return attr
		}
	}
	return none
}

// get_all returns every attribute of the given type, in wire order.
pub fn (m &Message) get_all(typ u16) []RawAttribute {
	mut out := []RawAttribute{}
	for attr in m.attributes {
		if attr.typ == typ {
			out << attr
		}
	}
	return out
}

// has reports whether an attribute of the given type is present.
pub fn (m &Message) has(typ u16) bool {
	return m.get(typ) != none
}

// unknown_comprehension_required returns the types of any comprehension-
// required attributes not in known. A server answers a request carrying these
// with a 420 error listing them, per RFC 8489 section 6.3.2.
pub fn (m &Message) unknown_comprehension_required(known []u16) []u16 {
	mut out := []u16{}
	for attr in m.attributes {
		if !is_comprehension_required(attr.typ) {
			continue
		}
		if attr.typ in known || attr.typ in out {
			continue
		}
		out << attr.typ
	}
	return out
}

// encode serialises the message, appending the authentication attributes
// requested in opts, and stores the result in m.raw.
pub fn (mut m Message) encode(opts EncodeOptions) ![]u8 {
	mut w := codec.Writer.with_capacity(header_size + 128)
	w.u16(m.typ.value())
	// Placeholder for the body length, patched once the body is known.
	w.u16(0)
	w.u32(magic_cookie)
	w.bytes(m.transaction_id[..])

	mut encoded := []RawAttribute{cap: m.attributes.len + 2}
	for attr in m.attributes {
		if attr.typ == attr_message_integrity || attr.typ == attr_message_integrity_sha256
			|| attr.typ == attr_fingerprint {
			// These are derived from the surrounding bytes. Accepting a
			// caller-supplied value would let a stale or forged digest through.
			return EncodeError{
				detail: '${attr_name(attr.typ)} must be requested through EncodeOptions, not added as an attribute'
			}
		}
		if attr.value.len > 0xFFFF {
			return EncodeError{
				detail: 'attribute ${attr.name()} value of ${attr.value.len} bytes exceeds the 16-bit length field'
			}
		}
		encoded << RawAttribute{
			typ:    attr.typ
			value:  attr.value
			offset: w.len()
		}
		write_attribute(mut w, attr.typ, attr.value)
	}

	if opts.integrity_key.len > 0 {
		typ, digest_len := match opts.integrity_algorithm {
			.sha1 { attr_message_integrity, sha1.size }
			.sha256 { attr_message_integrity_sha256, sha256.size }
		}

		offset := w.len()
		set_body_length(mut w.buf, offset + 4 + digest_len)
		digest := integrity_digest(w.buf, opts.integrity_key, opts.integrity_algorithm)
		encoded << RawAttribute{
			typ:    typ
			value:  digest
			offset: offset
		}
		write_attribute(mut w, typ, digest)
	}

	if opts.fingerprint {
		offset := w.len()
		set_body_length(mut w.buf, offset + 8)
		value := fingerprint_value(w.buf)
		encoded << RawAttribute{
			typ:    attr_fingerprint
			value:  value
			offset: offset
		}
		write_attribute(mut w, attr_fingerprint, value)
	}

	set_body_length(mut w.buf, w.len())
	m.raw = w.buf
	m.attributes = encoded
	return m.raw
}

// write_attribute emits one TLV, padded to a 4-byte boundary. The padding is
// not counted in the length field (RFC 8489 section 14).
fn write_attribute(mut w codec.Writer, typ u16, value []u8) {
	w.u16(typ)
	w.u16(u16(value.len))
	w.bytes(value)
	w.pad(4)
}

// set_body_length writes the STUN length field, which counts the bytes after
// the 20-byte header.
@[inline]
fn set_body_length(mut buf []u8, total_len int) {
	body := total_len - header_size
	buf[2] = u8(body >> 8)
	buf[3] = u8(body)
}

// Message.decode parses a STUN message.
//
// Everything reaching this function came off a socket, so every length is
// treated as hostile: the declared body length must agree with the buffer, each
// attribute must fit inside the body, and both the total size and the attribute
// count are capped.
pub fn Message.decode(b []u8, opts DecodeOptions) !Message {
	if b.len < header_size {
		return DecodeError{
			reason: .too_short
			detail: '${b.len} bytes is smaller than the ${header_size}-byte header'
		}
	}
	if b.len > opts.max_message_size {
		return DecodeError{
			reason: .too_large
			detail: '${b.len} bytes exceeds the ${opts.max_message_size}-byte limit'
		}
	}
	if b[0] & 0xC0 != 0 {
		return DecodeError{
			reason: .not_stun
			detail: 'leading bits of first byte are not zero'
		}
	}

	mut r := codec.Reader.new(b)
	raw_type := r.u16('message type')!
	body_len := int(r.u16('message length')!)
	cookie := r.u32('magic cookie')!
	if cookie != magic_cookie {
		return DecodeError{
			reason: .not_stun
			detail: 'magic cookie 0x${cookie.hex()} does not match 0x${magic_cookie.hex()}'
		}
	}
	if body_len % 4 != 0 {
		return DecodeError{
			reason: .bad_length
			detail: 'body length ${body_len} is not a multiple of 4'
		}
	}
	if header_size + body_len != b.len {
		return DecodeError{
			reason: .bad_length
			detail: 'body length ${body_len} does not match the ${b.len - header_size} bytes present'
		}
	}

	mut tid := [transaction_id_size]u8{}
	tid_bytes := r.view(transaction_id_size, 'transaction id')!
	for i in 0 .. transaction_id_size {
		tid[i] = tid_bytes[i]
	}

	mut attributes := []RawAttribute{}
	for r.remaining() > 0 {
		if attributes.len >= opts.max_attributes {
			return DecodeError{
				reason: .too_many_attributes
				detail: 'more than ${opts.max_attributes} attributes'
			}
		}
		offset := r.pos
		typ := r.u16('attribute type') or {
			return DecodeError{
				reason: .bad_attribute
				detail: 'truncated attribute header at offset ${offset}'
			}
		}
		value_len := int(r.u16('attribute length') or {
			return DecodeError{
				reason: .bad_attribute
				detail: 'truncated attribute header at offset ${offset}'
			}
		})
		value := r.bytes(value_len, 'attribute value') or {
			return DecodeError{
				reason: .bad_attribute
				detail: '${attr_name(typ)} declares ${value_len} bytes but only ${r.remaining()} remain'
			}
		}
		// Padding is present for every attribute except, possibly, the last one
		// in a message emitted by a non-conforming implementation. Being
		// tolerant here costs nothing and is what other stacks do.
		pad := padded_size(value_len) - value_len
		if pad > 0 && r.remaining() >= pad {
			r.skip(pad, 'attribute padding')!
		}
		attributes << RawAttribute{
			typ:    typ
			value:  value
			offset: offset
		}
	}

	return Message{
		typ:            MessageType.from_value(raw_type)
		transaction_id: tid
		attributes:     attributes
		raw:            b.clone()
	}
}

// integrity_digest computes the HMAC over the given prefix of a message.
fn integrity_digest(prefix []u8, key []u8, algorithm IntegrityAlgorithm) []u8 {
	return match algorithm {
		.sha1 { hmac.new(key, prefix, sha1.sum, sha1.block_size) }
		.sha256 { hmac.new(key, prefix, sha256.sum, sha256.block_size) }
	}
}

// fingerprint_value computes the FINGERPRINT payload over the given prefix.
fn fingerprint_value(prefix []u8) []u8 {
	v := crc32.sum(prefix) ^ fingerprint_xor
	return [u8(v >> 24), u8(v >> 16), u8(v >> 8), u8(v)]
}

// check_message_integrity verifies the MESSAGE-INTEGRITY attribute against key.
//
// The digest covers the message from its first byte up to the start of the
// MESSAGE-INTEGRITY attribute, with the header's length field set as though the
// message ended just after that attribute. Attributes that follow it are
// therefore unprotected, so anything other than FINGERPRINT or the SHA-256
// variant appearing after it is rejected rather than merely ignored.
pub fn (m &Message) check_message_integrity(key []u8) ! {
	m.check_integrity(attr_message_integrity, sha1.size, .sha1, key)!
}

// check_message_integrity_sha256 verifies the MESSAGE-INTEGRITY-SHA256
// attribute against key.
pub fn (m &Message) check_message_integrity_sha256(key []u8) ! {
	m.check_integrity(attr_message_integrity_sha256, sha256.size, .sha256, key)!
}

fn (m &Message) check_integrity(typ u16, digest_len int, algorithm IntegrityAlgorithm, key []u8) ! {
	if key.len == 0 {
		return IntegrityError{
			reason: .malformed
			detail: 'empty integrity key'
		}
	}
	attr := m.get(typ) or { return IntegrityError{
		reason: .missing
		detail: attr_name(typ)
	} }
	if attr.value.len != digest_len {
		return IntegrityError{
			reason: .malformed
			detail: '${attr_name(typ)} is ${attr.value.len} bytes, expected ${digest_len}'
		}
	}
	if attr.offset + 4 + digest_len > m.raw.len {
		return IntegrityError{
			reason: .malformed
			detail: '${attr_name(typ)} extends past the message'
		}
	}
	m.reject_unprotected_trailers(typ, attr.offset)!

	// Rebuild the protected prefix with the length field the sender used.
	mut prefix := m.raw[..attr.offset].clone()
	set_body_length(mut prefix, attr.offset + 4 + digest_len)
	expected := integrity_digest(prefix, key, algorithm)

	if !hmac.equal(expected, attr.value) {
		return IntegrityError{
			reason: .mismatch
			detail: attr_name(typ)
		}
	}
}

// reject_unprotected_trailers fails if an attribute that the digest does not
// cover follows the integrity attribute. RFC 8489 section 14.5 allows only
// MESSAGE-INTEGRITY-SHA256 and FINGERPRINT after MESSAGE-INTEGRITY, and only
// FINGERPRINT after MESSAGE-INTEGRITY-SHA256.
fn (m &Message) reject_unprotected_trailers(typ u16, offset int) ! {
	for attr in m.attributes {
		if attr.offset <= offset {
			continue
		}
		allowed := if typ == attr_message_integrity {
			attr.typ == attr_message_integrity_sha256 || attr.typ == attr_fingerprint
		} else {
			attr.typ == attr_fingerprint
		}
		if !allowed {
			return IntegrityError{
				reason: .not_last
				detail: '${attr.name()} follows ${attr_name(typ)} and is not covered by it'
			}
		}
	}
}

// check_fingerprint verifies the FINGERPRINT attribute.
//
// FINGERPRINT is not a security mechanism - a CRC-32 with a published XOR
// constant stops accidents, not attackers. Its purpose is demultiplexing: it
// tells a receiver that a datagram really is STUN and not another protocol that
// happens to start with the same bits.
pub fn (m &Message) check_fingerprint() ! {
	attr := m.get(attr_fingerprint) or {
		return IntegrityError{
			reason: .missing
			detail: 'FINGERPRINT'
		}
	}
	if attr.value.len != 4 {
		return IntegrityError{
			reason: .malformed
			detail: 'FINGERPRINT is ${attr.value.len} bytes, expected 4'
		}
	}
	// FINGERPRINT must be the final attribute.
	if attr.offset + 8 != m.raw.len {
		return IntegrityError{
			reason: .not_last
			detail: 'FINGERPRINT is not the last attribute'
		}
	}
	mut prefix := m.raw[..attr.offset].clone()
	set_body_length(mut prefix, attr.offset + 8)
	expected := fingerprint_value(prefix)
	if !hmac.equal(expected, attr.value) {
		return IntegrityError{
			reason: .mismatch
			detail: 'FINGERPRINT'
		}
	}
}

pub fn (m &Message) str() string {
	mut parts := []string{cap: m.attributes.len}
	for attr in m.attributes {
		parts << attr.str()
	}
	return '${m.typ} tid=${m.transaction_id[..].hex()} attrs=[${parts.join(', ')}]'
}
