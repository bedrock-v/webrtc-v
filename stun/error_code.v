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