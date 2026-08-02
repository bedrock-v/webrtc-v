module sctp

import webrtc.internal.codec

// The SCTP common header and packet framing (RFC 4960 section 3.1).

// packet_header_size is the twelve-byte common header.
pub const packet_header_size = 12

// checksum_offset is where the CRC-32c sits in the header.
const checksum_offset = 8

// default_max_chunks bounds how many chunks one packet may carry. Each one is
// work for the receiver, and the count comes from a peer that has not
// necessarily been authenticated yet.
pub const default_max_chunks = 64

// webrtc_port is the SCTP port both ends of a WebRTC association use. The value
// carries no meaning - there is one association per DTLS connection - but
// RFC 8841 fixes it at 5000 and the `a=sctp-port` attribute carries it.
pub const webrtc_port = u16(5000)