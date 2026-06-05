module stun

// RFC 8489 caps the textual attributes so a single message cannot be inflated
// with arbitrary text. The limits are in characters for USERNAME, REALM and
// NONCE, and the byte limits below are the UTF-8 worst case the RFC states.
pub const max_username_bytes = 513
pub const max_realm_bytes = 763
pub const max_nonce_bytes = 763
pub const max_software_bytes = 763