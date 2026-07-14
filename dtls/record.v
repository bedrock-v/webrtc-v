module dtls

import webrtc.internal.codec

// The DTLS record layer (RFC 6347 section 4.1).
//
// DTLS differs from TLS here in the two fields that make it work over a
// datagram transport: an explicit sequence number, because records can be
// reordered or lost, and an epoch, which counts how many times the keys have
// changed. Together they identify a record uniquely, which is what lets the
// replay window below reject a captured record without any per-connection
// state beyond a bitmask.

// record_header_size is the fixed 13-byte header.
pub const record_header_size = 13