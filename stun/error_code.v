module stun

// Error codes from the IANA STUN Error Codes registry. Only the ones a WebRTC
// endpoint can send or receive are named; others round-trip as their number.
pub const code_try_alternate = 300
pub const code_bad_request = 400
pub const code_unauthenticated = 401
pub const code_forbidden = 403
pub const code_unknown_attribute = 420
pub const code_allocation_mismatch = 437
pub const code_stale_nonce = 438
pub const code_address_family_not_supported = 440
pub const code_wrong_credentials = 441
pub const code_unsupported_transport_protocol = 442
pub const code_peer_address_family_mismatch = 443
pub const code_allocation_quota_reached = 486
pub const code_role_conflict = 487
pub const code_server_error = 500
pub const code_insufficient_capacity = 508

// max_reason_bytes is the RFC 8489 limit on the reason phrase.
pub const max_reason_bytes = 763

// ErrorCode is a decoded ERROR-CODE attribute.
pub struct ErrorCode {
pub:
	code   int
	reason string
}

pub fn (e ErrorCode) msg() string {
	return 'stun: ${e.code} ${e.reason}'
}

pub fn (e ErrorCode) code() int {
	return e.code
}

pub fn (e ErrorCode) str() string {
	return '${e.code} ${e.reason}'
}

// default_reason returns the registered reason phrase for a code, for use when
// building an error response.
pub fn default_reason(code int) string {
	return match code {
		code_try_alternate { 'Try Alternate' }
		code_bad_request { 'Bad Request' }
		code_unauthenticated { 'Unauthenticated' }
		code_forbidden { 'Forbidden' }
		code_unknown_attribute { 'Unknown Attribute' }
		code_allocation_mismatch { 'Allocation Mismatch' }
		code_stale_nonce { 'Stale Nonce' }
		code_address_family_not_supported { 'Address Family not Supported' }
		code_wrong_credentials { 'Wrong Credentials' }
		code_unsupported_transport_protocol { 'Unsupported Transport Protocol' }
		code_peer_address_family_mismatch { 'Peer Address Family Mismatch' }
		code_allocation_quota_reached { 'Allocation Quota Reached' }
		code_role_conflict { 'Role Conflict' }
		code_server_error { 'Server Error' }
		code_insufficient_capacity { 'Insufficient Capacity' }
		else { '' }
	}
}

// error_code returns the decoded ERROR-CODE attribute.
//
// The wire format splits the number: two bytes are reserved, the next holds the
// hundreds digit in its low three bits, and the last holds the remainder
// (RFC 8489 section 14.8).
pub fn (m &Message) error_code() !ErrorCode {
	attr := m.get(attr_error_code) or { return AttributeNotFoundError{
		typ: attr_error_code
	} }
	if attr.value.len < 4 {
		return DecodeError{
			reason: .bad_value
			detail: 'ERROR-CODE is ${attr.value.len} bytes, needs at least 4'
		}
	}
	if attr.value.len > 4 + max_reason_bytes {
		return DecodeError{
			reason: .bad_value
			detail: 'ERROR-CODE reason phrase exceeds ${max_reason_bytes} bytes'
		}
	}
	class := int(attr.value[2] & 0x07)
	number := int(attr.value[3])
	if class < 3 || class > 6 || number > 99 {
		return DecodeError{
			reason: .bad_value
			detail: 'ERROR-CODE ${class}${number:02} is outside the valid 300-699 range'
		}
	}
	reason_bytes := attr.value[4..]
	if !is_valid_utf8(reason_bytes) {
		return DecodeError{
			reason: .bad_value
			detail: 'ERROR-CODE reason phrase is not valid UTF-8'
		}
	}
	return ErrorCode{
		code:   class * 100 + number
		reason: reason_bytes.bytestr()
	}
}

// add_error_code appends an ERROR-CODE attribute. An empty reason is replaced
// by the registered phrase for the code.
pub fn (mut m Message) add_error_code(code int, reason string) ! {
	if code < 300 || code > 699 {
		return EncodeError{
			detail: 'ERROR-CODE ${code} is outside the valid 300-699 range'
		}
	}
	text := if reason == '' { default_reason(code) } else { reason }
	body := text.bytes()
	if body.len > max_reason_bytes {
		return EncodeError{
			detail: 'ERROR-CODE reason phrase is ${body.len} bytes, over the ${max_reason_bytes}-byte limit'
		}
	}
	mut value := []u8{cap: 4 + body.len}
	value << 0
	value << 0
	value << u8(code / 100)
	value << u8(code % 100)
	value << body
	m.add(attr_error_code, value)
}

// unknown_attributes returns the UNKNOWN-ATTRIBUTES list carried by a 420
// error, naming the comprehension-required attributes the peer could not
// process.
pub fn (m &Message) unknown_attributes() ![]u16 {
	attr := m.get(attr_unknown_attributes) or {
		return AttributeNotFoundError{
			typ: attr_unknown_attributes
		}
	}
	if attr.value.len % 2 != 0 {
		return DecodeError{
			reason: .bad_value
			detail: 'UNKNOWN-ATTRIBUTES is ${attr.value.len} bytes, not a whole number of types'
		}
	}
	mut out := []u16{cap: attr.value.len / 2}
	for i := 0; i < attr.value.len; i += 2 {
		out << (u16(attr.value[i]) << 8) | u16(attr.value[i + 1])
	}
	return out
}