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