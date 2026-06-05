module stun

// Error codes from the IANA STUN Error Codes registry. Only the ones a WebRTC
// endpoint can send or receive are named; others round-trip as their number.
pub const code_try_alternate = 300