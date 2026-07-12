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