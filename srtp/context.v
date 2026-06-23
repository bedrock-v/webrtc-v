module srtp

import webrtc.internal.aes
import crypto.hmac
import crypto.sha1
import webrtc.rtp

// srtcp_header_size is the part of an RTCP packet that is never encrypted: the
// common header and the sender's synchronisation source.
const srtcp_header_size = 8

// srtcp_index_size is the size of the trailing E-flag and index field.
const srtcp_index_size = 4

// max_srtcp_index is the largest value the 31-bit SRTCP index can hold. Once it
// is reached the master key must be replaced; continuing would repeat a counter
// block and destroy confidentiality.
const max_srtcp_index = u32(0x7FFFFFFF)

// ProtectionError is returned when a packet cannot be protected or unprotected.
pub struct ProtectionError {
pub:
	reason Reason
	detail string
}

pub enum Reason {
	// bad_input: the packet is malformed before any cryptography is attempted.
	bad_input
	// auth_failed: the authentication tag did not verify. The packet was
	// forged, corrupted, or protected with a different key.
	auth_failed
	// replayed: the packet index has already been accepted, or is too old to
	// judge.
	replayed
	// key_exhausted: the packet index space for this key is used up.
	key_exhausted
	// crypto_failed: an underlying primitive refused the input.
	crypto_failed
}