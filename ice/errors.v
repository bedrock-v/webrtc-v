module ice

// CandidateError is returned when a candidate cannot be parsed or is not usable.
pub struct CandidateError {
pub:
	detail string
}

pub fn (e CandidateError) msg() string {
	return 'ice: ${e.detail}'
}

pub fn (e CandidateError) code() int {
	return 1
}

// AgentError covers the failure modes of the agent itself.
pub struct AgentError {
pub:
	reason AgentErrorReason
	detail string
}

pub enum AgentErrorReason {
	// closed: the agent has been shut down.
	closed
	// wrong_state: the operation is not valid in the agent's current state, for
	// example adding a remote candidate before the remote credentials are known.
	wrong_state
	// no_candidates: gathering produced nothing usable.
	no_candidates
	// checks_failed: every candidate pair was tried and none succeeded.
	checks_failed
	// timed_out: connectivity was not established within the deadline.
	timed_out
	// bad_credentials: the credentials supplied are missing or malformed.
	bad_credentials
	// transport: an operating system socket call failed.
	transport
}