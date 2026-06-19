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