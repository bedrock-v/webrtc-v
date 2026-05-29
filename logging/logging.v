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

// level_from_string parses a level name, accepting the spellings used by the
// WEBRTC_LOG_LEVEL environment variable.
pub fn level_from_string(s string) !Level {
	return match s.to_lower().trim_space() {
		'disabled', 'off', 'none' { Level.disabled }
		'error' { Level.error }
		'warn', 'warning' { Level.warn }
		'info' { Level.info }
		'debug' { Level.debug }
		'trace' { Level.trace }
		else { error('logging: unknown level ${s}') }
	}
}

// Sink receives log records. Implementations must be safe to call from several
// threads, because the stack logs from its network read loops.
pub interface Sink {
	write(level Level, scope string, msg string)
}

// Logger is the handle components hold. It carries a scope name so records can
// be attributed to the subsystem that produced them, and a level so a noisy
// subsystem can be turned down without touching the rest.
//
// Logger is a value type: copying one is cheap and shares the underlying sink.
pub struct Logger {
pub:
	scope string
	sink  Sink = NopSink{}
pub mut:
	level Level
}

// new returns a Logger for the given scope backed by sink.
pub fn new(scope string, level Level, sink Sink) Logger {
	return Logger{
		scope: scope
		sink:  sink
		level: level
	}
}

// nop returns a Logger that discards everything. It is the default for
// components constructed without explicit configuration, so a library embedded
// in a quiet process stays quiet.
pub fn nop() Logger {
	return Logger{
		scope: ''
		sink:  NopSink{}
		level: .disabled
	}
}

// default returns a Logger writing to stderr at the given level.
pub fn default(scope string, level Level) Logger {
	return Logger{
		scope: scope
		sink:  StderrSink.new()
		level: level
	}
}

// from_env returns a Logger configured from the WEBRTC_LOG_LEVEL environment
// variable, falling back to warn when the variable is unset or unparseable.
pub fn from_env(scope string) Logger {
	raw := os.getenv('WEBRTC_LOG_LEVEL')
	if raw == '' {
		return default(scope, .warn)
	}
	level := level_from_string(raw) or { Level.warn }
	return default(scope, level)
}

// with_scope returns a copy of the logger under a nested scope, so a
// per-connection component can be told apart from its peers in the output.
pub fn (l Logger) with_scope(scope string) Logger {
	nested := if l.scope == '' { scope } else { '${l.scope}.${scope}' }
	return Logger{
		scope: nested
		sink:  l.sink
		level: l.level
	}
}