// Package datachannel implements WebRTC data channels: the DCEP establishment
// protocol of RFC 8832 and the message framing of RFC 8831, on top of an SCTP
// association.
//
// A data channel is one SCTP stream pair plus an agreement about how it
// behaves. SCTP already provides ordered and unordered delivery and partial
// reliability; DCEP is the two-message exchange that says which of them this
// channel wants, and gives it a label.
module datachannel

import webrtc.internal.codec

// DCEP message types (RFC 8832 section 8.2.1).
pub const message_type_ack = u8(0x02)
pub const message_type_open = u8(0x03)

// max_label_bytes and max_protocol_bytes bound the two strings in an OPEN
// message. Both come from a peer, and both are length-prefixed with 16 bits, so
// without a ceiling one message could ask us to allocate 128 KiB of text.
pub const max_label_bytes = 8192
pub const max_protocol_bytes = 8192