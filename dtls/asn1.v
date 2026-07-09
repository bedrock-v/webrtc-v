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

// der_bit_string encodes a bit string with no unused trailing bits, which is
// the only form X.509 uses for keys and signatures.
fn der_bit_string(value []u8) []u8 {
	mut body := []u8{cap: 1 + value.len}
	body << 0 // unused bits
	body << value
	return der_tlv(der_bit_string, body)
}

// der_oid encodes an object identifier from its dotted arc form.
//
// The first two arcs are packed into one byte as 40*a + b, and every arc is
// then base-128 with the continuation bit set on all but the last byte.
fn der_oid(dotted string) ![]u8 {
	parts := dotted.split('.')
	if parts.len < 2 {
		return Asn1Error{
			detail: 'object identifier "${dotted}" needs at least two arcs'
		}
	}
	mut arcs := []u64{cap: parts.len}
	for part in parts {
		arcs << parse_arc(part) or {
			return Asn1Error{
				detail: 'bad arc "${part}" in object identifier "${dotted}"'
			}
		}
	}
	if arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) {
		return Asn1Error{
			detail: 'object identifier "${dotted}" cannot be packed'
		}
	}

	mut body := []u8{}
	body << u8(arcs[0] * 40 + arcs[1])
	for arc in arcs[2..] {
		body << base128(arc)
	}
	return der_tlv(der_object_identifier, body)
}

fn parse_arc(s string) ?u64 {
	if s == '' || s.len > 19 {
		return none
	}
	mut value := u64(0)
	for c in s {
		if c < `0` || c > `9` {
			return none
		}
		value = value * 10 + u64(c - `0`)
	}
	return value
}

// base128 encodes an arc in the variable-length form DER uses for OIDs.
fn base128(value u64) []u8 {
	if value == 0 {
		return [u8(0)]
	}
	mut bytes := []u8{}
	mut v := value
	for v > 0 {
		bytes.prepend(u8(v & 0x7F))
		v >>= 7
	}
	for i in 0 .. bytes.len - 1 {
		bytes[i] |= 0x80
	}
	return bytes
}

// DerElement is one decoded tag-length-value triple.
struct DerElement {
	tag   u8
	value []u8
	// end is the offset just past this element in the buffer it came from.
	end int
}

// der_parse reads one element starting at offset.
fn der_parse(input []u8, offset int) !DerElement {
	if offset < 0 || offset >= input.len {
		return Asn1Error{
			detail: 'read past the end of the input'
		}
	}
	tag := input[offset]
	// High-tag-number form is not used anywhere in an X.509 certificate this
	// code needs to read, and supporting it would only widen the parser.
	if tag & 0x1F == 0x1F {
		return Asn1Error{
			detail: 'high tag numbers are not supported'
		}
	}
	if offset + 1 >= input.len {
		return Asn1Error{
			detail: 'truncated length'
		}
	}

	first := input[offset + 1]
	mut length := 0
	mut header := 2
	if first & 0x80 == 0 {
		length = int(first)
	} else {
		count := int(first & 0x7F)
		if count == 0 {
			return Asn1Error{
				detail: 'indefinite length is not valid DER'
			}
		}
		if count > 4 {
			return Asn1Error{
				detail: 'length of ${count} bytes exceeds what this decoder accepts'
			}
		}
		if offset + 2 + count > input.len {
			return Asn1Error{
				detail: 'truncated long-form length'
			}
		}
		if input[offset + 2] == 0 {
			return Asn1Error{
				detail: 'non-minimal length encoding'
			}
		}
		for i in 0 .. count {
			length = int((u32(length) << 8) | u32(input[offset + 2 + i]))
		}
		if length < 0x80 {
			return Asn1Error{
				detail: 'long-form length used for a value that fits the short form'
			}
		}
		header = 2 + count
	}

	if length > max_der_length {
		return Asn1Error{
			detail: 'element of ${length} bytes exceeds the ${max_der_length}-byte limit'
		}
	}
	if offset + header + length > input.len {
		return Asn1Error{
			detail: 'element declares ${length} bytes but only ${input.len - offset - header} remain'
		}
	}
	return DerElement{
		tag:   tag
		value: input[offset + header..offset + header + length]
		end:   offset + header + length
	}
}

// der_children decodes the elements inside a constructed value.
fn der_children(value []u8) ![]DerElement {
	mut out := []DerElement{}
	mut offset := 0
	for offset < value.len {
		element := der_parse(value, offset)!
		out << element
		offset = element.end
	}
	return out
}
