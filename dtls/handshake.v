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

// max_handshake_body bounds one reassembled message. A certificate is the
// largest thing that crosses this layer and is a few hundred bytes; the limit
// is what stops a peer from declaring a 16 MiB message and making us hold a
// buffer for it.
pub const max_handshake_body = 65536

// random_size is the size of a hello random: four bytes of time and 28 random.
pub const random_size = 32

// max_cookie_size is the RFC 6347 limit on a HelloVerifyRequest cookie.
pub const max_cookie_size = 255