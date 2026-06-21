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