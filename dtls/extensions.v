module dtls

import webrtc.internal.codec
import webrtc.srtp

// TLS extensions, as carried in the DTLS ClientHello and ServerHello.
//
// Only the ones a WebRTC handshake needs are decoded into typed structures. The
// rest round-trip as raw bytes, which is what lets an unrecognised extension
// from a peer be echoed or ignored without being lost.

// Extension type numbers from the IANA TLS ExtensionType registry.
pub const ext_supported_groups = u16(10)
pub const ext_ec_point_formats = u16(11)
pub const ext_signature_algorithms = u16(13)
pub const ext_use_srtp = u16(14)
pub const ext_extended_master_secret = u16(23)
pub const ext_renegotiation_info = u16(65281)

// max_extensions bounds how many extensions one hello may carry. The list comes
// from the peer before anything is authenticated.
const max_extensions = 32

// NamedCurve identifies an elliptic curve for key exchange (RFC 8422).
pub enum NamedCurve as u16 {
	secp256r1 = 23
	secp384r1 = 24
	secp521r1 = 25
	x25519    = 29
}

// EcPointFormat is how an elliptic curve point is encoded. Only uncompressed is
// mandatory to implement, and it is the only one anything deployed uses.
pub enum EcPointFormat as u8 {
	uncompressed = 0
}

// HashAlgorithmId and SignatureAlgorithmId are the two halves of a TLS 1.2
// SignatureAndHashAlgorithm (RFC 5246 section 7.4.1.4.1).
pub enum HashAlgorithmId as u8 {
	sha1   = 2
	sha256 = 4
	sha384 = 5
	sha512 = 6
}