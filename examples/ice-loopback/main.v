// Connect two ICE agents to each other inside one process.
//
// Run with: v run examples/ice-loopback
//
// The two agents are what a real deployment would have on two different
// machines. Everything they exchange here through direct calls - credentials
// and candidates - is exactly what a real deployment sends through its
// signalling channel, and nothing else passes between them: the media path is
// negotiated by ICE over real UDP sockets.
module main

import time
import webrtc.ice
import webrtc.logging

fn main() {
	log := logging.from_env('example')

	// Loopback is off by default, because a loopback candidate can only pair
	// with the same machine. Here that is exactly what we want.
	interfaces := ice.InterfaceOptions{
		include_loopback: true
	}

	mut caller := ice.Agent.new(
		role:           .controlling
		interfaces:     interfaces
		logger:         log.with_scope('caller')
		check_interval: 20 * time.millisecond
	)!
	defer {
		caller.close()
	}

	mut callee := ice.Agent.new(
		role:           .controlled
		interfaces:     interfaces
		logger:         log.with_scope('callee')
		check_interval: 20 * time.millisecond
	)!
	defer {
		callee.close()
	}

	// --- Signalling: credentials -------------------------------------------
	caller_ufrag, caller_pwd := caller.local_credentials()
	callee_ufrag, callee_pwd := callee.local_credentials()
	println('caller credentials: ${caller_ufrag} / ${caller_pwd[..6]}...')
	println('callee credentials: ${callee_ufrag} / ${callee_pwd[..6]}...')

	caller.set_remote_credentials(callee_ufrag, callee_pwd)!
	callee.set_remote_credentials(caller_ufrag, caller_pwd)!

	// --- Gathering ---------------------------------------------------------
	println('\ngathering...')
	caller.gather()!
	callee.gather()!

	// --- Signalling: candidates --------------------------------------------
	println('\ncaller candidates:')
	for candidate in caller.local_candidates() {
		println('  a=candidate:${candidate}')
		callee.add_remote_candidate(candidate)!
	}
	println('callee candidates:')
	for candidate in callee.local_candidates() {
		println('  a=candidate:${candidate}')
		caller.add_remote_candidate(candidate)!
	}

	// --- Connectivity ------------------------------------------------------
	println('\nchecking...')
	started := time.now()
	caller.connect(20 * time.second)!
	callee.connect(20 * time.second)!
	println('connected in ${(time.now() - started).milliseconds()}ms')

	if pair := caller.selected_pair() {
		println('selected pair: ${pair}')
		println('  round trip:  ${pair.round_trip_time.microseconds()}us')
	}

	// --- Data --------------------------------------------------------------
	println('')
	caller.send('ping'.bytes())!
	received := callee.recv(5 * time.second)!
	println('callee received: ${received.bytestr()}')

	callee.send('pong'.bytes())!
	reply := caller.recv(5 * time.second)!
	println('caller received: ${reply.bytestr()}')

	// Nomination happens after the first pair succeeds, so the state settles a
	// moment later.
	deadline := time.now().add(5 * time.second)
	for time.now() < deadline {
		if caller.state() == .completed && callee.state() == .completed {
			break
		}
		time.sleep(20 * time.millisecond)
	}

	println('')
	stats := caller.statistics()
	println('caller: state=${stats.state} role=${stats.role}')
	println('  candidates: ${stats.local_candidates} local, ${stats.remote_candidates} remote')
	println('  pairs:      ${stats.pairs} total, ${stats.succeeded_pairs} succeeded, ${stats.failed_pairs} failed')
}
