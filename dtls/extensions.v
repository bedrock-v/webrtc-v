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

// RenegotiationInfo signals that the sender understands RFC 5746. WebRTC never
// renegotiates, so the payload is always empty, but several stacks refuse a
// handshake that omits the extension entirely.
pub struct RenegotiationInfo {
pub:
	renegotiated_connection []u8
}

// RawExtension is an extension this implementation does not interpret.
pub struct RawExtension {
pub:
	typ  u16
	data []u8
}

// extension_type returns the wire type number of an extension.
pub fn (e Extension) extension_type() u16 {
	return match e {
		SupportedGroups { ext_supported_groups }
		SupportedEcPointFormats { ext_ec_point_formats }
		SupportedSignatureAlgorithms { ext_signature_algorithms }
		UseSrtp { ext_use_srtp }
		ExtendedMasterSecret { ext_extended_master_secret }
		RenegotiationInfo { ext_renegotiation_info }
		RawExtension { e.typ }
	}
}

// marshal_body serialises just the extension_data field.
fn (e Extension) marshal_body() ![]u8 {
	match e {
		SupportedGroups {
			mut w := codec.Writer.new()
			w.u16(u16(e.curves.len * 2))
			for curve in e.curves {
				w.u16(u16(curve))
			}
			return w.buf
		}
		SupportedEcPointFormats {
			mut w := codec.Writer.new()
			w.u8(u8(e.formats.len))
			for format in e.formats {
				w.u8(u8(format))
			}
			return w.buf
		}
		SupportedSignatureAlgorithms {
			mut w := codec.Writer.new()
			w.u16(u16(e.schemes.len * 2))
			for scheme in e.schemes {
				w.u8(u8(scheme.hash))
				w.u8(u8(scheme.signature))
			}
			return w.buf
		}
		UseSrtp {
			if e.mki.len > 255 {
				return HandshakeError{
					detail: 'SRTP MKI of ${e.mki.len} bytes exceeds the 255-byte field'
				}
			}
			mut w := codec.Writer.new()
			w.u16(u16(e.profiles.len * 2))
			for profile in e.profiles {
				w.u16(u16(profile))
			}
			w.u8(u8(e.mki.len))
			w.bytes(e.mki)
			return w.buf
		}
		ExtendedMasterSecret {
			return []u8{}
		}
		RenegotiationInfo {
			if e.renegotiated_connection.len > 255 {
				return HandshakeError{
					detail: 'renegotiation info of ${e.renegotiated_connection.len} bytes exceeds the 255-byte field'
				}
			}
			mut w := codec.Writer.new()
			w.u8(u8(e.renegotiated_connection.len))
			w.bytes(e.renegotiated_connection)
			return w.buf
		}
		RawExtension {
			return e.data.clone()
		}
	}
}

// marshal_extensions serialises a whole extension list, including the two-byte
// length prefix that precedes it in a hello.
fn marshal_extensions(extensions []Extension) ![]u8 {
	mut body := codec.Writer.new()
	for extension in extensions {
		payload := extension.marshal_body()!
		if payload.len > 0xFFFF {
			return HandshakeError{
				detail: 'extension ${extension.extension_type()} is ${payload.len} bytes, over the 16-bit limit'
			}
		}
		body.u16(extension.extension_type())
		body.u16(u16(payload.len))
		body.bytes(payload)
	}
	if body.len() > 0xFFFF {
		return HandshakeError{
			detail: 'extension list of ${body.len()} bytes exceeds the 16-bit length field'
		}
	}
	mut w := codec.Writer.with_capacity(2 + body.len())
	w.u16(u16(body.len()))
	w.bytes(body.buf)
	return w.buf
}

// unmarshal_extensions decodes an extension list, given the bytes after the
// two-byte list length.
//
// An extension whose body is malformed is kept as a RawExtension rather than
// failing the handshake. That is deliberate: a peer sending something we cannot
// parse in an extension we do not act on should not prevent a connection, and
// the extensions we do act on are validated where they are used.
fn unmarshal_extensions(data []u8) ![]Extension {
	mut out := []Extension{}
	mut r := codec.Reader.new(data)

	for r.remaining() > 0 {
		if out.len >= max_extensions {
			return HandshakeError{
				detail: 'more than ${max_extensions} extensions'
			}
		}
		typ := r.u16('extension type') or {
			return HandshakeError{
				detail: 'truncated extension header'
			}
		}
		length := int(r.u16('extension length') or {
			return HandshakeError{
				detail: 'truncated extension header'
			}
		})
		body := r.bytes(length, 'extension body') or {
			return HandshakeError{
				detail: 'extension ${typ} declares ${length} bytes but only ${r.remaining()} remain'
			}
		}
		out << decode_extension(typ, body)
	}
	return out
}

fn decode_extension(typ u16, body []u8) Extension {
	// Each arm falls through to RawExtension when the body does not decode, so
	// an extension we cannot parse is preserved rather than fatal.
	match typ {
		ext_supported_groups {
			if decoded := decode_supported_groups(body) {
				return decoded
			}
		}
		ext_ec_point_formats {
			if decoded := decode_ec_point_formats(body) {
				return decoded
			}
		}
		ext_signature_algorithms {
			if decoded := decode_signature_algorithms(body) {
				return decoded
			}
		}
		ext_use_srtp {
			if decoded := decode_use_srtp(body) {
				return decoded
			}
		}
		ext_extended_master_secret {
			// The extension is a flag; a non-empty body is malformed.
			if body.len == 0 {
				return ExtendedMasterSecret{}
			}
		}
		ext_renegotiation_info {
			if body.len >= 1 && int(body[0]) == body.len - 1 {
				return RenegotiationInfo{
					renegotiated_connection: body[1..].clone()
				}
			}
		}
		else {}
	}
	return RawExtension{
		typ:  typ
		data: body
	}
}

fn decode_supported_groups(body []u8) ?SupportedGroups {
	mut r := codec.Reader.new(body)
	length := int(r.u16('groups length') or { return none })
	if length % 2 != 0 || r.remaining() < length {
		return none
	}
	mut curves := []NamedCurve{cap: length / 2}
	for _ in 0 .. length / 2 {
		value := r.u16('group') or { return none }
		// Unknown curves are kept, so that a later comparison against what we
		// support sees exactly what the peer offered.
		curves << unsafe { NamedCurve(value) }
	}
	return SupportedGroups{
		curves: curves
	}
}

fn decode_ec_point_formats(body []u8) ?SupportedEcPointFormats {
	mut r := codec.Reader.new(body)
	length := int(r.u8('formats length') or { return none })
	if r.remaining() < length {
		return none
	}
	mut formats := []EcPointFormat{cap: length}
	for _ in 0 .. length {
		value := r.u8('format') or { return none }
		formats << unsafe { EcPointFormat(value) }
	}
	return SupportedEcPointFormats{
		formats: formats
	}
}

fn decode_signature_algorithms(body []u8) ?SupportedSignatureAlgorithms {
	mut r := codec.Reader.new(body)
	length := int(r.u16('algorithms length') or { return none })
	if length % 2 != 0 || r.remaining() < length {
		return none
	}
	mut schemes := []SignatureScheme{cap: length / 2}
	for _ in 0 .. length / 2 {
		hash := r.u8('hash') or { return none }
		signature := r.u8('signature') or { return none }
		schemes << SignatureScheme{
			hash:      unsafe { HashAlgorithmId(hash) }
			signature: unsafe { SignatureAlgorithmId(signature) }
		}
	}
	return SupportedSignatureAlgorithms{
		schemes: schemes
	}
}