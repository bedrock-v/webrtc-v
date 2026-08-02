module sctp

import webrtc.internal.codec

// The SCTP common header and packet framing (RFC 4960 section 3.1).

// packet_header_size is the twelve-byte common header.
pub const packet_header_size = 12