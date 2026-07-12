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

// der_length encodes a length in DER's definite form: short for values under
// 128, and otherwise a byte count followed by the big-endian minimal encoding.
fn der_length(n int) []u8 {
	if n < 0x80 {
		return [u8(n)]
	}
	mut bytes := []u8{}
	mut value := n
	for value > 0 {
		bytes.prepend(u8(value))
		value >>= 8
	}
	mut out := [u8(0x80 | bytes.len)]
	out << bytes
	return out
}

// der_tlv wraps a value in a tag and length.
fn der_tlv(tag u8, value []u8) []u8 {
	mut out := []u8{cap: 2 + value.len}
	out << tag
	out << der_length(value.len)
	out << value
	return out
}

// der_sequence_of concatenates the elements and wraps them in a SEQUENCE.
fn der_sequence_of(elements ...[]u8) []u8 {
	mut body := []u8{}
	for element in elements {
		body << element
	}
	return der_tlv(der_sequence, body)
}

// der_integer_from_bytes encodes an unsigned big-endian value as an INTEGER.
//
// DER integers are signed, so a value whose top bit is set needs a leading zero
// byte or it would decode as negative. Leading zeros are otherwise stripped,
// because DER requires the minimal encoding.
fn der_integer_from_bytes(value []u8) []u8 {
	mut start := 0
	for start < value.len - 1 && value[start] == 0 {
		start++
	}
	mut body := value[start..].clone()
	if body.len == 0 {
		body = [u8(0)]
	} else if body[0] & 0x80 != 0 {
		body.prepend(u8(0))
	}
	return der_tlv(der_integer, body)
}