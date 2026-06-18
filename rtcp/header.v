// Package rtcp implements the RTP Control Protocol (RFC 3550) and the feedback
// messages WebRTC congestion control and error resilience depend on: NACK and
// TMMBR from RFC 4585 and RFC 5104, PLI and FIR, REMB, and transport-wide
// congestion control feedback.
//
// Like the rtp package, this one is about packets rather than sessions. It does
// not decide when a report should be sent or what it should contain; it
// serialises what a caller has decided.
module rtcp

import webrtc.internal.codec

// version is the only RTCP version in use.
pub const version = u8(2)

// header_size is the size of the common header that precedes every packet.
pub const header_size = 4

// Packet types from the IANA RTP/RTCP registry.
pub const pt_sender_report = u8(200)
pub const pt_receiver_report = u8(201)
pub const pt_source_description = u8(202)
pub const pt_goodbye = u8(203)
pub const pt_application_defined = u8(204)
pub const pt_transport_feedback = u8(205)
pub const pt_payload_feedback = u8(206)
pub const pt_extended_report = u8(207)

// Feedback message subtypes carried in the count field of a 205 or 206 packet.
pub const fmt_nack = u8(1)
pub const fmt_pli = u8(1)
pub const fmt_sli = u8(2)
pub const fmt_tmmbr = u8(3)
pub const fmt_tmmbn = u8(4)
pub const fmt_fir = u8(4)
pub const fmt_transport_cc = u8(15)
pub const fmt_application_layer = u8(15)

// max_packet_size bounds a single RTCP packet. The length field can express
// 256 KiB, far more than any real report needs; a lower ceiling limits what one
// spoofed datagram costs.
pub const max_packet_size = 8192

// max_packets_per_compound bounds how many packets one datagram may carry.
pub const max_packets_per_compound = 32

// DecodeError describes why a byte string is not valid RTCP.
pub struct DecodeError {
pub:
	reason DecodeReason
	detail string
}

pub enum DecodeReason {
	too_short
	bad_version
	bad_length
	bad_padding
	bad_value
	too_many_packets
}

pub fn (e DecodeError) msg() string {
	return 'rtcp: ${e.reason}: ${e.detail}'
}

pub fn (e DecodeError) code() int {
	return int(e.reason) + 1
}

// EncodeError is returned when a packet cannot be represented on the wire.
pub struct EncodeError {
pub:
	detail string
}

pub fn (e EncodeError) msg() string {
	return 'rtcp: ${e.detail}'
}

pub fn (e EncodeError) code() int {
	return 100
}

// Header is the four-byte header common to every RTCP packet.
pub struct Header {
pub mut:
	// count is the report count for a report packet, or the feedback message
	// type for a 205 or 206 packet. The field is five bits wide either way.
	count u8
	// padding marks that the packet is followed by padding bytes, the last of
	// which gives their number. Only the final packet of a compound datagram
	// may carry it.
	padding bool
	// packet_type identifies the packet.
	packet_type u8
	// length is the packet size in 32-bit words minus one, as it appears on the
	// wire. It is derived on encode and is only meaningful after a decode.
	length u16
}

// byte_length returns the total size of the packet the header describes.
@[inline]
pub fn (h &Header) byte_length() int {
	return (int(h.length) + 1) * 4
}

fn (h &Header) marshal_into(mut w codec.Writer, body_len int) ! {
	if h.count > 31 {
		return EncodeError{
			detail: 'count ${h.count} does not fit the 5-bit field'
		}
	}
	total := header_size + body_len
	if total % 4 != 0 {
		return EncodeError{
			detail: 'packet body of ${body_len} bytes is not a whole number of words'
		}
	}
	words := total / 4 - 1
	if words > 0xFFFF {
		return EncodeError{
			detail: 'packet of ${total} bytes exceeds the 16-bit length field'
		}
	}
	mut first := version << 6
	if h.padding {
		first |= 0x20
	}
	first |= h.count
	w.u8(first)
	w.u8(h.packet_type)
	w.u16(u16(words))
}

fn decode_header(mut r codec.Reader) !Header {
	first := r.u8('flags') or {
		return DecodeError{
			reason: .too_short
			detail: 'no room for the common header'
		}
	}
	ver := first >> 6
	if ver != version {
		return DecodeError{
			reason: .bad_version
			detail: 'version ${ver} is not 2'
		}
	}
	packet_type := r.u8('packet type') or {
		return DecodeError{
			reason: .too_short
			detail: 'truncated common header'
		}
	}
	length := r.u16('length') or {
		return DecodeError{
			reason: .too_short
			detail: 'truncated common header'
		}
	}
	return Header{
		count:       first & 0x1F
		padding:     first & 0x20 != 0
		packet_type: packet_type
		length:      length
	}
}