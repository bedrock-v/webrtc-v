module ice

import time

// PairState is where a candidate pair sits in the check list
// (RFC 8445 section 6.1.2.6).
pub enum PairState {
	// frozen: not yet eligible. A pair is frozen while another pair with the
	// same foundation is still being checked, so that redundant probes are not
	// sent down paths that are about to be proven equivalent.
	frozen
	// waiting: eligible, not yet sent.
	waiting
	// in_progress: a check has been sent and no response has arrived.
	in_progress
	// succeeded: a check completed and the path works in both directions.
	succeeded
	// failed: the check timed out or was answered with an error.
	failed
}

pub fn (s PairState) str() string {
	return match s {
		.frozen { 'frozen' }
		.waiting { 'waiting' }
		.in_progress { 'in-progress' }
		.succeeded { 'succeeded' }
		.failed { 'failed' }
	}
}

// CandidatePair is one local candidate paired with one remote candidate.
pub struct CandidatePair {
pub:
	local  Candidate
	remote Candidate
pub mut:
	state PairState = .frozen
	// nominated marks the pair the controlling agent has selected. Once a
	// nominated pair succeeds, checking stops and media flows over it.
	nominated bool
	// binding_requests counts how many checks have been sent, so that a pair
	// can be given up on after a bounded number of attempts.
	binding_requests int
	last_sent        time.Time
	// last_received is when traffic last arrived on this pair. Consent
	// freshness (RFC 7675) uses it to decide whether the path is still alive.
	last_received time.Time
	// round_trip_time is measured from the most recent successful check.
	round_trip_time time.Duration
}