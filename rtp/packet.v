// Package rtp implements the RTP packet format (RFC 3550) and the header
// extension mechanism WebRTC relies on (RFC 8285).
//
// The package is deliberately about packets, not about sessions: it has no
// timers, no jitter buffer and no notion of a stream. Higher layers compose
// those on top. That split keeps the parser - the part that touches bytes from
// the network - small enough to reason about completely.
module rtp

import webrtc.internal.codec

// version is the only RTP version this implementation accepts. Version 1 and 0
// are historical and are not deployed.
pub const version = u8(2)

// header_size is the size of the fixed part of the header, before CSRCs.
pub const header_size = 12

// extension_profile_one_byte is the profile identifier for the one-byte header
// extension form of RFC 8285 section 4.2.
pub const extension_profile_one_byte = u16(0xBEDE)

// extension_profile_two_byte_base is the profile identifier for the two-byte
// form (RFC 8285 section 4.3). The low four bits carry an appbits field, so the
// profile is matched by masking.
pub const extension_profile_two_byte_base = u16(0x1000)

// max_csrc is the number of contributing sources the four-bit CC field can
// express.
pub const max_csrc = 15

// DecodeError describes why a datagram is not a valid RTP packet.
pub struct DecodeError {
pub:
	reason DecodeReason
	detail string
}

pub enum DecodeReason {
	too_short
	bad_version
	bad_padding
	bad_extension
	bad_csrc
}

pub fn (e DecodeError) msg() string {
	return 'rtp: ${e.reason}: ${e.detail}'
}

pub fn (e DecodeError) code() int {
	return int(e.reason) + 1
}

// EncodeError is returned when a header cannot be represented on the wire.
pub struct EncodeError {
pub:
	detail string
}

pub fn (e EncodeError) msg() string {
	return 'rtp: ${e.detail}'
}

pub fn (e EncodeError) code() int {
	return 100
}

// Extension is one RFC 8285 header extension element.
pub struct Extension {
pub:
	// id is the local identifier negotiated through an SDP extmap attribute.
	// One-byte extensions use 1-14; two-byte extensions use 1-255.
	id u8
	// payload is the extension body, 1-16 bytes in the one-byte form and
	// 0-255 in the two-byte form.
	payload []u8
}

// Header is the RTP header.
pub struct Header {
pub mut:
	version         u8 = version
	padding         bool
	marker          bool
	payload_type    u8
	sequence_number u16
	timestamp       u32
	ssrc            u32
	csrc            []u32
	// extension_profile is set when extensions are present. It records which
	// of the two RFC 8285 forms was used, so a packet re-marshals the way it
	// arrived instead of being silently converted.
	extension_profile u16
	extensions        []Extension
}

// has_extensions reports whether the header carries any extension elements.
@[inline]
pub fn (h &Header) has_extensions() bool {
	return h.extensions.len > 0
}

// uses_two_byte_extensions reports which RFC 8285 form the header uses.
@[inline]
pub fn (h &Header) uses_two_byte_extensions() bool {
	return h.extension_profile & 0xFFF0 == extension_profile_two_byte_base
}

// extension returns the payload of the extension with the given id.
pub fn (h &Header) extension(id u8) ?[]u8 {
	for ext in h.extensions {
		if ext.id == id {
			return ext.payload
		}
	}
	return none
}

// set_extension adds or replaces an extension element.
//
// The profile is chosen automatically when the header has none: a payload that
// fits the one-byte form uses it, since it costs one byte less per element and
// is what receivers are most likely to accept. Once a profile is fixed, adding
// an element that does not fit it is an error rather than a silent upgrade,
// because changing the profile mid-stream would invalidate elements already
// written by the caller.
pub fn (mut h Header) set_extension(id u8, payload []u8) ! {
	if id == 0 {
		return EncodeError{
			detail: 'extension id 0 is reserved for padding'
		}
	}
	if h.extension_profile == 0 {
		h.extension_profile = if id <= 14 && payload.len >= 1 && payload.len <= 16 {
			extension_profile_one_byte
		} else {
			extension_profile_two_byte_base
		}
	}
	if h.uses_two_byte_extensions() {
		if payload.len > 255 {
			return EncodeError{
				detail: 'two-byte extension ${id} payload is ${payload.len} bytes, over the 255-byte limit'
			}
		}
	} else {
		if id > 14 {
			return EncodeError{
				detail: 'extension id ${id} does not fit the one-byte form, which allows 1-14'
			}
		}
		if payload.len < 1 || payload.len > 16 {
			return EncodeError{
				detail: 'one-byte extension ${id} payload is ${payload.len} bytes, outside the 1-16 range'
			}
		}
	}

	for i, ext in h.extensions {
		if ext.id == id {
			h.extensions[i] = Extension{
				id:      id
				payload: payload.clone()
			}
			return
		}
	}
	h.extensions << Extension{
		id:      id
		payload: payload.clone()
	}
}

// delete_extension removes an extension element, reporting whether one was
// present.
pub fn (mut h Header) delete_extension(id u8) bool {
	for i, ext in h.extensions {
		if ext.id == id {
			h.extensions.delete(i)
			if h.extensions.len == 0 {
				h.extension_profile = 0
			}
			return true
		}
	}
	return false
}

// Packet is an RTP packet.
pub struct Packet {
pub mut:
	header  Header
	payload []u8
	// padding_size is the number of padding bytes that followed the payload,
	// including the length byte itself. It is preserved so that a packet
	// re-marshals to the same length, which matters when a packet has already
	// been counted or authenticated at that size.
	padding_size int
}

// is_rtp reports whether a datagram looks like RTP or RTCP.
//
// This is the RFC 7983 demultiplexing test for the 128-191 range. Telling RTP
// from RTCP within that range needs the payload type, which is what
// is_rtcp_payload_type is for.
pub fn is_rtp(b []u8) bool {
	if b.len < header_size {
		return false
	}
	return b[0] & 0xC0 == 0x80
}

// is_rtcp_payload_type reports whether a packet in the RTP range is RTCP.
//
// RFC 5761 section 4 reserves RTP payload types 64-95 so that, with the marker
// bit, they cannot collide with the RTCP packet types 200-223. That reservation
// is what makes rtcp-mux possible.
pub fn is_rtcp_payload_type(b []u8) bool {
	if b.len < 2 {
		return false
	}
	pt := b[1] & 0x7F
	return pt >= 64 && pt <= 95
}

// header_length returns the number of bytes the header occupies, including the
// contributing source list and any header extension.
//
// It exists so that SRTP can find the boundary between the part of a packet it
// authenticates and the part it encrypts without parsing and allocating a whole
// Packet for every datagram on the wire.
pub fn header_length(b []u8) !int {
	if b.len < header_size {
		return DecodeError{
			reason: .too_short
			detail: '${b.len} bytes is smaller than the ${header_size}-byte header'
		}
	}
	if b[0] >> 6 != version {
		return DecodeError{
			reason: .bad_version
			detail: 'version ${b[0] >> 6} is not 2'
		}
	}
	mut length := header_size + int(b[0] & 0x0F) * 4
	if b[0] & 0x10 == 0 {
		if length > b.len {
			return DecodeError{
				reason: .bad_csrc
				detail: 'CSRC list runs past the end of the packet'
			}
		}
		return length
	}
	// The extension header is four bytes: a profile and a length in words.
	if length + 4 > b.len {
		return DecodeError{
			reason: .bad_extension
			detail: 'extension flag set but the extension header does not fit'
		}
	}
	words := int((u16(b[length + 2]) << 8) | u16(b[length + 3]))
	length += 4 + words * 4
	if length > b.len {
		return DecodeError{
			reason: .bad_extension
			detail: 'extension body runs past the end of the packet'
		}
	}
	return length
}

// Packet.decode parses an RTP packet.
pub fn Packet.decode(b []u8) !Packet {
	mut r := codec.Reader.new(b)
	if b.len < header_size {
		return DecodeError{
			reason: .too_short
			detail: '${b.len} bytes is smaller than the ${header_size}-byte header'
		}
	}

	first := r.u8('flags')!
	ver := first >> 6
	if ver != version {
		return DecodeError{
			reason: .bad_version
			detail: 'version ${ver} is not 2'
		}
	}
	has_padding := first & 0x20 != 0
	has_extension := first & 0x10 != 0
	csrc_count := int(first & 0x0F)

	second := r.u8('marker and payload type')!
	mut header := Header{
		version:         version
		padding:         has_padding
		marker:          second & 0x80 != 0
		payload_type:    second & 0x7F
		sequence_number: r.u16('sequence number')!
		timestamp:       r.u32('timestamp')!
		ssrc:            r.u32('ssrc')!
	}

	header.csrc = []u32{cap: csrc_count}
	for i in 0 .. csrc_count {
		header.csrc << r.u32('csrc ${i}') or {
			return DecodeError{
				reason: .bad_csrc
				detail: 'CC declares ${csrc_count} sources but the packet holds ${i}'
			}
		}
	}

	if has_extension {
		header.extension_profile = r.u16('extension profile') or {
			return DecodeError{
				reason: .bad_extension
				detail: 'extension flag set but no extension header present'
			}
		}
		words := int(r.u16('extension length') or {
			return DecodeError{
				reason: .bad_extension
				detail: 'truncated extension header'
			}
		})
		body := r.view(words * 4, 'extension body') or {
			return DecodeError{
				reason: .bad_extension
				detail: 'extension declares ${words * 4} bytes but only ${r.remaining()} remain'
			}
		}
		header.extensions = parse_extensions(header.extension_profile, body)!
	}

	mut payload := r.rest_view()

	// Padding is stripped before the payload is handed to the caller: the
	// length byte is the last byte of the packet and it counts itself.
	mut padding_size := 0
	if has_padding {
		if payload.len == 0 {
			return DecodeError{
				reason: .bad_padding
				detail: 'padding flag set but the packet has no payload'
			}
		}
		padding_size = int(payload[payload.len - 1])
		if padding_size == 0 || padding_size > payload.len {
			return DecodeError{
				reason: .bad_padding
				detail: 'padding length ${padding_size} does not fit the ${payload.len}-byte payload'
			}
		}
		payload = unsafe { payload[..payload.len - padding_size] }
	}

	return Packet{
		header:       header
		payload:      payload.clone()
		padding_size: padding_size
	}
}

// parse_extensions decodes the body of an RFC 8285 extension block.
fn parse_extensions(profile u16, body []u8) ![]Extension {
	mut out := []Extension{}
	mut r := codec.Reader.new(body)

	if profile == extension_profile_one_byte {
		for r.remaining() > 0 {
			b := r.u8('extension header')!
			// Identifier 0 is a padding byte and carries no length.
			if b == 0 {
				continue
			}
			id := b >> 4
			// Identifier 15 marks the end of the extension list: a receiver
			// must stop parsing, because what follows is padding chosen by the
			// sender and is not an element.
			if id == 15 {
				break
			}
			length := int(b & 0x0F) + 1
			payload := r.bytes(length, 'extension ${id} payload') or {
				return DecodeError{
					reason: .bad_extension
					detail: 'one-byte extension ${id} declares ${length} bytes but only ${r.remaining()} remain'
				}
			}
			out << Extension{
				id:      id
				payload: payload
			}
		}
		return out
	}

	if profile & 0xFFF0 == extension_profile_two_byte_base {
		for r.remaining() > 0 {
			id := r.u8('extension id')!
			if id == 0 {
				continue
			}
			length := int(r.u8('extension length') or {
				return DecodeError{
					reason: .bad_extension
					detail: 'two-byte extension ${id} has no length byte'
				}
			})
			payload := r.bytes(length, 'extension ${id} payload') or {
				return DecodeError{
					reason: .bad_extension
					detail: 'two-byte extension ${id} declares ${length} bytes but only ${r.remaining()} remain'
				}
			}
			out << Extension{
				id:      id
				payload: payload
			}
		}
		return out
	}

	// A profile outside RFC 8285 identifies a single opaque extension. It is
	// kept whole under id 0 so the packet still round-trips, rather than being
	// dropped or misparsed as elements.
	if body.len > 0 {
		out << Extension{
			id:      0
			payload: body.clone()
		}
	}
	return out
}

// marshal serialises the packet.
pub fn (p &Packet) marshal() ![]u8 {
	if p.header.version != version {
		return EncodeError{
			detail: 'cannot marshal version ${p.header.version}, only version 2 is supported'
		}
	}
	if p.header.csrc.len > max_csrc {
		return EncodeError{
			detail: '${p.header.csrc.len} contributing sources exceed the ${max_csrc} the CC field can express'
		}
	}
	if p.header.payload_type > 127 {
		return EncodeError{
			detail: 'payload type ${p.header.payload_type} does not fit 7 bits'
		}
	}
	if p.padding_size < 0 || p.padding_size > 255 {
		return EncodeError{
			detail: 'padding size ${p.padding_size} does not fit the length byte'
		}
	}

	extension_body := encode_extensions(p.header)!
	has_extension := extension_body.len > 0
	// The padding flag and the padding bytes must agree, or a receiver either
	// reads garbage as payload or truncates real payload.
	needs_padding := p.padding_size > 0

	mut w := codec.Writer.with_capacity(header_size + p.header.csrc.len * 4 + extension_body.len +
		p.payload.len + p.padding_size)

	mut first := version << 6
	if needs_padding {
		first |= 0x20
	}
	if has_extension {
		first |= 0x10
	}
	first |= u8(p.header.csrc.len)
	w.u8(first)

	mut second := p.header.payload_type
	if p.header.marker {
		second |= 0x80
	}
	w.u8(second)
	w.u16(p.header.sequence_number)
	w.u32(p.header.timestamp)
	w.u32(p.header.ssrc)
	for source in p.header.csrc {
		w.u32(source)
	}
	if has_extension {
		w.bytes(extension_body)
	}
	w.bytes(p.payload)
	if needs_padding {
		w.zeros(p.padding_size - 1)
		w.u8(u8(p.padding_size))
	}
	return w.buf
}