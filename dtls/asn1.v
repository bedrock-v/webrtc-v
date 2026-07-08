module dtls

// A minimal ASN.1 DER encoder and decoder, enough for the X.509 certificates
// DTLS needs and nothing more.
//
// DER is a canonical encoding: every value has exactly one valid representation.
// That property is what makes a certificate fingerprint meaningful, so the
// encoder here always emits the canonical form and the decoder rejects
// non-canonical input rather than accepting it leniently.

// DER tag numbers, with the class and constructed bits already applied.
const der_boolean = u8(0x01)
const der_integer = u8(0x02)
const der_bit_string = u8(0x03)
const der_octet_string = u8(0x04)
const der_null = u8(0x05)
const der_object_identifier = u8(0x06)
const der_utf8_string = u8(0x0C)
const der_printable_string = u8(0x13)
const der_utc_time = u8(0x17)
const der_generalized_time = u8(0x18)
const der_sequence = u8(0x30)
const der_set = u8(0x31)

// der_context_constructed builds a constructed context-specific tag, which
// X.509 uses for its optional fields: [0] for the version, [3] for extensions.
@[inline]
fn der_context_constructed(number u8) u8 {
	return 0xA0 | (number & 0x1F)
}

// max_der_length bounds a decoded length field. A certificate is a few hundred
// bytes; anything claiming megabytes is either corrupt or an attempt to make us
// allocate.
const max_der_length = 1 << 20

// Asn1Error is returned when input is not valid DER.
pub struct Asn1Error {
pub:
	detail string
}

pub fn (e Asn1Error) msg() string {
	return 'dtls: asn1: ${e.detail}'
}

pub fn (e Asn1Error) code() int {
	return 1
}