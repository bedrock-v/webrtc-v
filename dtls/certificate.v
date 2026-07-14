module dtls

import crypto.ecdsa
import crypto.sha1
import crypto.sha256
import crypto.sha512
import time
import webrtc.internal.randutil

// Certificate generation and fingerprinting.
//
// WebRTC does not use a certificate authority. Each endpoint generates a
// self-signed certificate, publishes its fingerprint in the SDP, and the
// handshake is authenticated by checking that the certificate the peer
// presented hashes to the fingerprint that was signalled (RFC 8122). The chain
// of trust runs through the signalling channel, not through a CA, which is why
// none of the usual path validation appears here - and why the fingerprint
// check is not optional.

// Object identifiers used in the certificates this package produces.
const oid_ec_public_key = '1.2.840.10045.2.1'
const oid_prime256v1 = '1.2.840.10045.3.1.7'
const oid_ecdsa_with_sha256 = '1.2.840.10045.4.3.2'
const oid_common_name = '2.5.4.3'

// default_certificate_lifetime is how long a generated certificate is valid.
//
// Thirty days is far longer than any call and short enough that a leaked key
// stops being useful. The value matters less than it would with a CA, because
// the fingerprint in the SDP is what actually authenticates the peer.
pub const default_certificate_lifetime = 30 * 24 * time.hour

// HashAlgorithm is a certificate fingerprint hash. RFC 8122 registers several;
// SHA-256 is what every browser signals.
pub enum HashAlgorithm {
	sha1
	sha256
	sha384
	sha512
}

pub fn (h HashAlgorithm) str() string {
	return match h {
		.sha1 { 'sha-1' }
		.sha256 { 'sha-256' }
		.sha384 { 'sha-384' }
		.sha512 { 'sha-512' }
	}
}

// hash_algorithm_from_string parses the name used in an SDP fingerprint line.
pub fn hash_algorithm_from_string(s string) ?HashAlgorithm {
	return match s.to_lower() {
		'sha-1' { HashAlgorithm.sha1 }
		'sha-256' { HashAlgorithm.sha256 }
		'sha-384' { HashAlgorithm.sha384 }
		'sha-512' { HashAlgorithm.sha512 }
		else { none }
	}
}

fn (h HashAlgorithm) sum(data []u8) []u8 {
	return match h {
		.sha1 { sha1.sum(data) }
		.sha256 { sha256.sum(data) }
		.sha384 { sha512.sum384(data) }
		.sha512 { sha512.sum512(data) }
	}
}

// CertificateError is returned when a certificate cannot be generated, parsed
// or verified.
pub struct CertificateError {
pub:
	detail string
}

pub fn (e CertificateError) msg() string {
	return 'dtls: ${e.detail}'
}

pub fn (e CertificateError) code() int {
	return 2
}

// Certificate is a self-signed certificate and the key that signed it.
pub struct Certificate {
pub:
	// der is the certificate in its DER encoding, which is what goes on the
	// wire and what the fingerprint is computed over.
	der []u8
pub mut:
	private_key ecdsa.PrivateKey
	public_key  ecdsa.PublicKey
}

// Fingerprint is a certificate hash as it appears in an SDP a=fingerprint line.
pub struct Fingerprint {
pub:
	algorithm HashAlgorithm
	// value is the lowercase, colon-separated hex of the digest.
	value string
}

pub fn (f Fingerprint) str() string {
	return '${f.algorithm} ${f.value}'
}

// Fingerprint.parse reads an SDP fingerprint value such as
// "sha-256 AB:CD:...".
pub fn Fingerprint.parse(input string) !Fingerprint {
	fields := input.split(' ').filter(it != '')
	if fields.len != 2 {
		return CertificateError{
			detail: 'fingerprint "${input}" has ${fields.len} fields, expected 2'
		}
	}
	algorithm := hash_algorithm_from_string(fields[0]) or {
		return CertificateError{
			detail: 'unsupported fingerprint hash "${fields[0]}"'
		}
	}
	value := fields[1].to_lower()
	for c in value {
		if !((c >= `0` && c <= `9`) || (c >= `a` && c <= `f`) || c == `:`) {
			return CertificateError{
				detail: 'fingerprint value contains an unexpected character'
			}
		}
	}
	return Fingerprint{
		algorithm: algorithm
		value:     value
	}
}

// matches reports whether two fingerprints are the same.
//
// The comparison is on the normalised hex text rather than on raw bytes,
// because a fingerprint arrives as text from signalling. It is deliberately not
// constant-time: a certificate fingerprint is public, and the value being
// compared against is one the peer just sent us.
pub fn (f Fingerprint) matches(other Fingerprint) bool {
	return f.algorithm == other.algorithm && f.value == other.value
}

// fingerprint computes the certificate's fingerprint under the given hash.
pub fn (c &Certificate) fingerprint(algorithm HashAlgorithm) Fingerprint {
	digest := algorithm.sum(c.der)
	return Fingerprint{
		algorithm: algorithm
		value:     colon_hex(digest)
	}
}

// fingerprint_of computes the fingerprint of a DER certificate we did not
// generate, which is how a peer's certificate is checked against the SDP.
pub fn fingerprint_of(der []u8, algorithm HashAlgorithm) Fingerprint {
	return Fingerprint{
		algorithm: algorithm
		value:     colon_hex(algorithm.sum(der))
	}
}

fn colon_hex(digest []u8) string {
	mut parts := []string{cap: digest.len}
	for b in digest {
		parts << b.hex()
	}
	return parts.join(':')
}

// CertificateOptions configures generation.
@[params]
pub struct CertificateOptions {
pub:
	// common_name goes in the subject and issuer. It carries no meaning here -
	// nothing validates it - so it defaults to a random string rather than to
	// anything identifying.
	common_name string
	lifetime    time.Duration = default_certificate_lifetime
	// not_before_skew backdates the validity period to tolerate a peer whose
	// clock is behind ours. Without it, two machines a minute apart can fail to
	// connect for reasons neither can see.
	not_before_skew time.Duration = time.hour
}

// Certificate.generate creates a self-signed P-256 certificate.
pub fn Certificate.generate(opts CertificateOptions) !Certificate {
	public_key, private_key := ecdsa.generate_key(nid: .prime256v1) or {
		return CertificateError{
			detail: 'generating a P-256 key: ${err.msg()}'
		}
	}
	return Certificate.from_key(private_key, public_key, opts)!
}

// Certificate.from_key builds a self-signed certificate around an existing key,
// for an application that wants to keep one identity across restarts.
pub fn Certificate.from_key(private_key ecdsa.PrivateKey, public_key ecdsa.PublicKey, opts CertificateOptions) !Certificate {
	common_name := if opts.common_name != '' {
		opts.common_name
	} else {
		'WebRTC-${randutil.alphanumeric_string(16)!}'
	}

	// A serial number must be positive and unique per issuer. Since every
	// certificate here is its own issuer, random is sufficient; 20 bytes is the
	// maximum X.509 allows.
	serial := randutil.bytes(20)!

	now := time.now()
	not_before := now.add(-opts.not_before_skew)
	not_after := now.add(opts.lifetime)

	point := public_key.uncompressed_bytes() or {
		return CertificateError{
			detail: 'reading the public key point: ${err.msg()}'
		}
	}

	algorithm := der_sequence_of(der_oid(oid_ecdsa_with_sha256)!)
	subject_public_key_info := der_sequence_of(der_sequence_of(der_oid(oid_ec_public_key)!,
		der_oid(oid_prime256v1)!), der_bit_string(point))
	name := encode_common_name(common_name)!
	validity := der_sequence_of(encode_time(not_before), encode_time(not_after))

	tbs := der_sequence_of(
		// [0] EXPLICIT version, 2 meaning v3.
		der_tlv(der_context_constructed(0), der_integer_from_bytes([u8(2)])),
		der_integer_from_bytes(serial),
		algorithm,
		name,
		validity,
		name,
		subject_public_key_info,
	)

	// The signature is over the DER of the TBSCertificate, with SHA-256 chosen
	// by the recommended-hash setting for a P-256 key.
	signature := private_key.sign(tbs) or {
		return CertificateError{
			detail: 'signing the certificate: ${err.msg()}'
		}
	}

	der := der_sequence_of(tbs, algorithm, der_bit_string(signature))
	return Certificate{
		der:         der
		private_key: private_key
		public_key:  public_key
	}
}

// encode_common_name builds the Name structure for a single CN attribute.
fn encode_common_name(name string) ![]u8 {
	bytes := name.bytes()
	if bytes.len == 0 || bytes.len > 64 {
		return CertificateError{
			detail: 'common name must be 1 to 64 bytes, got ${bytes.len}'
		}
	}
	attribute := der_sequence_of(der_oid(oid_common_name)!, der_tlv(der_utf8_string, bytes))
	return der_tlv(der_sequence, der_tlv(der_set, attribute))
}

// encode_time writes a validity bound.
//
// X.509 requires UTCTime for years through 2049 and GeneralizedTime after, and
// DER requires the seconds field and the trailing Z.
fn encode_time(t time.Time) []u8 {
	// time.now() is local; the certificate must carry UTC.
	utc := t.local_to_utc()
	if utc.year < 2050 {
		text := '${utc.year % 100:02d}${utc.month:02d}${utc.day:02d}${utc.hour:02d}${utc.minute:02d}${utc.second:02d}Z'
		return der_tlv(der_utc_time, text.bytes())
	}
	text := '${utc.year:04d}${utc.month:02d}${utc.day:02d}${utc.hour:02d}${utc.minute:02d}${utc.second:02d}Z'
	return der_tlv(der_generalized_time, text.bytes())
}

// ParsedCertificate is what this package reads back out of a peer's
// certificate: enough to complete the handshake and no more.
//
// There is deliberately no path validation, no name checking and no expiry
// enforcement beyond what is described below. In WebRTC the certificate is not
// trusted because of who signed it; it is trusted because its fingerprint
// matches the one that arrived over the signalling channel.
pub struct ParsedCertificate {
pub:
	der []u8
	// public_key is the peer's key, used to verify its CertificateVerify.
	public_key ecdsa.PublicKey
	not_before time.Time
	not_after  time.Time
}

// parse_certificate reads the fields needed from a DER certificate.
pub fn parse_certificate(der []u8) !ParsedCertificate {
	certificate := der_parse(der, 0)!
	if certificate.tag != der_sequence {
		return CertificateError{
			detail: 'certificate is not a SEQUENCE'
		}
	}
	if certificate.end != der.len {
		return CertificateError{
			detail: 'trailing bytes after the certificate'
		}
	}

	top := der_children(certificate.value)!
	if top.len != 3 {
		return CertificateError{
			detail: 'certificate has ${top.len} fields, expected 3'
		}
	}
	tbs := der_children(top[0].value)!

	// The version is an optional [0] field; when present it shifts every later
	// field along by one.
	mut index := 0
	if tbs.len > 0 && tbs[0].tag == der_context_constructed(0) {
		index = 1
	}
	// serial, signature algorithm, issuer, validity, subject, spki
	if tbs.len < index + 6 {
		return CertificateError{
			detail: 'certificate is missing required fields'
		}
	}

	validity := der_children(tbs[index + 3].value)!
	if validity.len != 2 {
		return CertificateError{
			detail: 'validity has ${validity.len} fields, expected 2'
		}
	}
	not_before := decode_time(validity[0])!
	not_after := decode_time(validity[1])!

	spki := der_children(tbs[index + 5].value)!
	if spki.len != 2 {
		return CertificateError{
			detail: 'subjectPublicKeyInfo has ${spki.len} fields, expected 2'
		}
	}
	if spki[1].tag != der_bit_string || spki[1].value.len < 2 {
		return CertificateError{
			detail: 'subjectPublicKey is not a usable BIT STRING'
		}
	}
	if spki[1].value[0] != 0 {
		return CertificateError{
			detail: 'subjectPublicKey has unused trailing bits'
		}
	}
	point := spki[1].value[1..]
	public_key := ecdsa.PublicKey.from_uncompressed_bytes(point, nid: .prime256v1) or {
		return CertificateError{
			detail: 'peer public key is not a valid P-256 point: ${err.msg()}'
		}
	}

	return ParsedCertificate{
		der:        der.clone()
		public_key: public_key
		not_before: not_before
		not_after:  not_after
	}
}

// decode_time reads a UTCTime or GeneralizedTime.
fn decode_time(element DerElement) !time.Time {
	text := element.value.bytestr()
	match element.tag {
		der_utc_time {
			if text.len != 13 || !text.ends_with('Z') {
				return CertificateError{
					detail: 'UTCTime "${text}" is not in the DER form YYMMDDHHMMSSZ'
				}
			}
			// RFC 5280 section 4.1.2.5.1: years 50 through 99 mean 19xx, and 00
			// through 49 mean 20xx.
			two_digit := two_digits(text, 0)!
			year := if two_digit >= 50 { 1900 + two_digit } else { 2000 + two_digit }
			return build_time(year, text, 2)!
		}
		der_generalized_time {
			if text.len != 15 || !text.ends_with('Z') {
				return CertificateError{
					detail: 'GeneralizedTime "${text}" is not in the DER form YYYYMMDDHHMMSSZ'
				}
			}
			year := two_digits(text, 0)! * 100 + two_digits(text, 2)!
			return build_time(year, text, 4)!
		}
		else {
			return CertificateError{
				detail: 'validity field has tag 0x${element.tag.hex()}, expected a time'
			}
		}
	}
}

fn build_time(year int, text string, offset int) !time.Time {
	return time.new(
		year:   year
		month:  two_digits(text, offset)!
		day:    two_digits(text, offset + 2)!
		hour:   two_digits(text, offset + 4)!
		minute: two_digits(text, offset + 6)!
		second: two_digits(text, offset + 8)!
	)
}