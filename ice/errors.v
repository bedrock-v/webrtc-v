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