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

// IntegrityError is returned when MESSAGE-INTEGRITY or FINGERPRINT validation
// fails. A caller must treat every variant as "discard the message": a missing
// attribute is as fatal as a wrong one, otherwise an attacker could strip
// authentication by omitting it.
pub struct IntegrityError {
pub:
	reason IntegrityReason
	detail string
}

pub enum IntegrityReason {
	// missing: the message carries no attribute of the required kind.
	missing
	// mismatch: the computed value differs from the transmitted one.
	mismatch
	// malformed: the attribute is present but the wrong length.
	malformed
	// not_last: an attribute followed MESSAGE-INTEGRITY that is not permitted
	// to, which would let an attacker append content outside the protection.
	not_last
}

pub fn (e IntegrityError) msg() string {
	return 'stun: integrity ${e.reason}: ${e.detail}'
}

pub fn (e IntegrityError) code() int {
	return int(e.reason) + 200
}

// AttributeNotFoundError is returned by typed getters when the attribute is
// absent, so that "absent" and "present but corrupt" stay distinguishable.
pub struct AttributeNotFoundError {
pub:
	typ u16
}