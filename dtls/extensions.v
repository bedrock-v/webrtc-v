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

pub enum SignatureAlgorithmId as u8 {
	rsa   = 1
	ecdsa = 3
}

// SignatureScheme pairs a hash with a signature algorithm.
pub struct SignatureScheme {
pub:
	hash      HashAlgorithmId
	signature SignatureAlgorithmId
}

// ecdsa_sha256 is the only scheme this implementation signs with. It is what a
// P-256 certificate calls for and what every browser offers.
pub const ecdsa_sha256 = SignatureScheme{
	hash:      .sha256
	signature: .ecdsa
}

// Extension is one entry in a hello's extension list.
//
// The typed variants carry the extensions this implementation acts on; Raw
// keeps everything else intact.
pub type Extension = ExtendedMasterSecret
	| RawExtension
	| RenegotiationInfo
	| SupportedEcPointFormats
	| SupportedGroups
	| SupportedSignatureAlgorithms
	| UseSrtp

// SupportedGroups lists the curves the sender will accept for key exchange.
pub struct SupportedGroups {
pub:
	curves []NamedCurve
}

// SupportedEcPointFormats lists the point encodings the sender accepts.
pub struct SupportedEcPointFormats {
pub:
	formats []EcPointFormat
}

// SupportedSignatureAlgorithms lists the signature schemes the sender accepts.
pub struct SupportedSignatureAlgorithms {
pub:
	schemes []SignatureScheme
}

// UseSrtp negotiates the SRTP protection profile (RFC 5764 section 4.1).
//
// This extension is what makes DTLS-SRTP work: the DTLS handshake agrees an
// SRTP profile and then, instead of carrying the media itself, exports keying
// material for it.
pub struct UseSrtp {
pub:
	profiles []srtp.Profile
	// mki is the master key identifier. WebRTC does not use one, and this
	// implementation sends it empty; a non-empty value from a peer is preserved
	// so it can be echoed.
	mki []u8
}

// ExtendedMasterSecret is a flag: its presence asks for RFC 7627 key
// derivation, which binds the master secret to the handshake transcript.
pub struct ExtendedMasterSecret {}