// Package logging provides the leveled logger used throughout the WebRTC
// stack.
//
// The library never writes to stdout and never picks a logging framework for
// the application. It emits records through the Sink interface; the default
// sink writes human-readable lines to stderr and is quiet below the warn level,
// so a library user who configures nothing sees only what they need to act on.
module logging

import io
import os
import sync
import time
import strings

// Level orders log severities. Comparisons rely on the declared order, so new
// levels must be inserted in severity order.
pub enum Level {
	disabled = 0
	error    = 1
	warn     = 2
	info     = 3
	debug    = 4
	trace    = 5
}

// str returns the lowercase name used in log output and configuration.
pub fn (l Level) str() string {
	return match l {
		.disabled { 'disabled' }
		.error { 'error' }
		.warn { 'warn' }
		.info { 'info' }
		.debug { 'debug' }
		.trace { 'trace' }
	}
}