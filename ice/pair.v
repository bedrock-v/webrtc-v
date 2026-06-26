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

// priority returns the pair priority (RFC 8445 section 6.1.2.3).
//
//	priority = 2^32 * min(G, D) + 2 * max(G, D) + (G > D ? 1 : 0)
//
// G is the controlling agent's candidate priority and D the controlled one's.
// The formula is built so that both agents compute the same ordering from the
// same two numbers, which is what lets them work through the check list in step
// without any extra coordination.
pub fn (p &CandidatePair) priority(local_is_controlling bool) u64 {
	g, d := if local_is_controlling {
		u64(p.local.priority), u64(p.remote.priority)
	} else {
		u64(p.remote.priority), u64(p.local.priority)
	}
	min_priority := if g < d { g } else { d }
	max_priority := if g > d { g } else { d }
	tiebreak := if g > d { u64(1) } else { u64(0) }
	return (min_priority << 32) + 2 * max_priority + tiebreak
}

// foundation is the pair's foundation: the two candidate foundations joined.
// Pairs sharing one are redundant with each other.
pub fn (p &CandidatePair) foundation() string {
	return '${p.local.foundation}:${p.remote.foundation}'
}

pub fn (p &CandidatePair) str() string {
	return '${p.local.typ}:${p.local.address} -> ${p.remote.typ}:${p.remote.address} [${p.state}${if p.nominated {
		', nominated'
	} else {
		''
	}}]'
}

// pairable reports whether two candidates can be paired.
//
// RFC 8445 section 6.1.2.2 only pairs candidates of the same component and the
// same address family. Pairing across families would produce checks that cannot
// possibly succeed and would crowd out ones that can.
fn pairable(local Candidate, remote Candidate) bool {
	if local.component != remote.component {
		return false
	}
	if local.transport != remote.transport {
		return false
	}
	if local.address.family() != remote.address.family() {
		return false
	}
	// A link-local IPv6 address is only reachable within its own scope, and the
	// zone identifier is not something the peer can meaningfully act on.
	if local.address.ip.is_link_local() != remote.address.ip.is_link_local() {
		return false
	}
	return true
}

// sort_pairs orders a check list by descending pair priority, which is the
// order RFC 8445 section 6.1.2.3 requires checks to be attempted in.
fn sort_pairs(mut pairs []CandidatePair, local_is_controlling bool) {
	if pairs.len < 2 {
		// V 0.5.2 faults inside its stable sort on an empty array, and a check
		// list is legitimately empty until the peer's candidates arrive.
		return
	}
	pairs.sort_with_compare(fn [local_is_controlling] (a &CandidatePair, b &CandidatePair) int {
		pa := a.priority(local_is_controlling)
		pb := b.priority(local_is_controlling)
		if pa > pb {
			return -1
		}
		if pa < pb {
			return 1
		}
		return 0
	})
}
