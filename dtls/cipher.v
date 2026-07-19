module dtls

import webrtc.internal.aes
import webrtc.internal.codec

// AEAD record protection for TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
// (RFC 5288, as applied to DTLS by RFC 6347).
//
// The nonce is split: four bytes come from the key block and never appear on
// the wire, and eight are sent with each record. Since a repeated nonce under
// the same key destroys GCM completely, the explicit half is the record's
// epoch and sequence number rather than a counter of our own - those are
// already unique per record and are already in the header.

// gcm_key_length is the AES-128 key size.
const gcm_key_length = 16