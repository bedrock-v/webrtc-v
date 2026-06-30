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