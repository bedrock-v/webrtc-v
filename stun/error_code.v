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