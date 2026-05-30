module stun

// DecodeError covers every way a byte string can fail to be a STUN message.
// The reason is a machine-readable discriminant so callers - notably the ICE
// agent, which must decide whether to answer, ignore or log - can branch
// without string matching.
pub struct DecodeError {
pub:
	reason DecodeReason
	detail string
}