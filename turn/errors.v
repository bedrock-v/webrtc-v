module turn

// TurnError is returned when a relay cannot be used.
pub struct TurnError {
pub:
	reason TurnErrorReason
	detail string
	// code is the STUN error code the server sent, when the failure came from
	// the server rather than from us. It is worth keeping: 401 and 438 are
	// routine parts of the exchange, 403 and 486 mean the credentials are fine
	// but the request will never be granted, and the difference decides whether
	// retrying is sensible.
	code int
}