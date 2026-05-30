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