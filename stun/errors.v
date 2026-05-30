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

pub enum DecodeReason {
	// too_short: fewer than 20 bytes, so the header itself does not fit.
	too_short
	// not_stun: leading two bits are not zero, or the magic cookie is absent.
	not_stun
	// bad_length: the declared body length disagrees with the buffer, or is not
	// a multiple of 4.
	bad_length
	// bad_attribute: an attribute runs past the end of the message.
	bad_attribute
	// too_large: the message exceeds the configured size limit.
	too_large
	// too_many_attributes: the attribute count exceeds the configured limit.
	too_many_attributes
	// bad_value: an attribute's payload is not valid for its type.
	bad_value
}

pub fn (e DecodeError) msg() string {
	return 'stun: ${e.reason}: ${e.detail}'
}

pub fn (e DecodeError) code() int {
	return int(e.reason) + 100
}