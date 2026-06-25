module srtp

import webrtc.internal.aes

// Key derivation labels from RFC 3711 section 4.3.1. Each derived key comes
// from the same master key under a different label, so that compromising one
// session key does not reveal the others.
const label_srtp_encryption = u8(0x00)
const label_srtp_auth = u8(0x01)
const label_srtp_salt = u8(0x02)
const label_srtcp_encryption = u8(0x03)
const label_srtcp_auth = u8(0x04)
const label_srtcp_salt = u8(0x05)

// aes_block_size is the AES block size in bytes.
const aes_block_size = 16