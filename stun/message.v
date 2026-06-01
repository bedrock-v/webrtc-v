module stun

import crypto.hmac
import crypto.sha1
import crypto.sha256
import hash.crc32
import webrtc.internal.codec
import webrtc.internal.randutil

// magic_cookie is the fixed value in bytes 4..8 of every STUN message
// (RFC 8489 section 5). It is what lets a receiver tell STUN apart from other
// protocols multiplexed on the same socket.
pub const magic_cookie = u32(0x2112A442)

// header_size is the size of the fixed STUN header.
pub const header_size = 20

// transaction_id_size is the length of the transaction identifier.
pub const transaction_id_size = 12

// fingerprint_xor is XORed into the CRC-32 in a FINGERPRINT attribute
// (RFC 8489 section 14.7), so that a plain CRC never appears on the wire.
pub const fingerprint_xor = u32(0x5354554e)

// default_max_message_size bounds how much memory one message may consume.
// The length field is 16 bits, but nothing in WebRTC needs anywhere near that,
// and a lower ceiling limits what a single spoofed datagram can cost us.
pub const default_max_message_size = 8192