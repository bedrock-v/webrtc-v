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