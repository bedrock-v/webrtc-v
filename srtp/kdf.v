module srtp

import webrtc.internal.aes

// Key derivation labels from RFC 3711 section 4.3.1. Each derived key comes
// from the same master key under a different label, so that compromising one
// session key does not reveal the others.
const label_srtp_encryption = u8(0x00)