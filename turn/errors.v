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

pub enum TurnErrorReason {
	// closed: the client has been closed.
	closed
	// transport: a socket operation failed.
	transport
	// timed_out: the server did not answer.
	timed_out
	// unauthorized: the server rejected the credentials.
	unauthorized
	// refused: the server understood the request and declined it.
	refused
	// bad_message: the server sent something that does not decode, or a caller
	// supplied something that cannot be encoded.
	bad_message
	// no_allocation: the operation needs an allocation and there is none.
	no_allocation
	// unsupported: the server offered only something this client does not do.
	unsupported
}

pub fn (e TurnError) msg() string {
	if e.code != 0 {
		return 'turn: ${e.reason}: ${e.detail} (server code ${e.code})'
	}
	return 'turn: ${e.reason}: ${e.detail}'
}

pub fn (e TurnError) code() int {
	return int(e.reason) + 60
}
