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