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