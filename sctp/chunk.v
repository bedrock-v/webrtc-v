module sctp

import webrtc.internal.codec

// SCTP chunks (RFC 4960 section 3.2).
//
// Every chunk is type, flags, a 16-bit length that counts the four header bytes
// but not the padding, and a value padded to a four-byte boundary. Several
// chunks travel in one packet, which is how an association acknowledges data
// and sends more in the same datagram.

// chunk_header_size is the four-byte type, flags and length.
pub const chunk_header_size = 4