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