// Package rtcp implements the RTP Control Protocol (RFC 3550) and the feedback
// messages WebRTC congestion control and error resilience depend on: NACK and
// TMMBR from RFC 4585 and RFC 5104, PLI and FIR, REMB, and transport-wide
// congestion control feedback.
//
// Like the rtp package, this one is about packets rather than sessions. It does
// not decide when a report should be sent or what it should contain; it
// serialises what a caller has decided.
module rtcp