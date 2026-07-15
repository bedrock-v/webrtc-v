module dtls

import webrtc.internal.codec
import webrtc.internal.randutil

// The DTLS handshake protocol (RFC 6347 section 4.2, on top of RFC 5246
// section 7.4).
//
// A handshake message carries three fields TLS does not have: a message
// sequence number, and a fragment offset and length. Together they let one
// logical message be split across several records, which is what makes a
// certificate larger than the path MTU deliverable over UDP.

// handshake_header_size is the fixed 12-byte header.
pub const handshake_header_size = 12