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

// with_level returns a copy of the logger at a different level.
pub fn (l Logger) with_level(level Level) Logger {
	return Logger{
		scope: l.scope
		sink:  l.sink
		level: level
	}
}

// enabled reports whether records at the given level would be emitted. Call it
// before building an expensive message.
@[inline]
pub fn (l Logger) enabled(level Level) bool {
	return l.level != .disabled && int(level) <= int(l.level)
}

@[inline]
fn (l Logger) emit(level Level, msg string) {
	if !l.enabled(level) {
		return
	}
	l.sink.write(level, l.scope, msg)
}

pub fn (l Logger) error(msg string) {
	l.emit(.error, msg)
}

pub fn (l Logger) warn(msg string) {
	l.emit(.warn, msg)
}

pub fn (l Logger) info(msg string) {
	l.emit(.info, msg)
}

pub fn (l Logger) debug(msg string) {
	l.emit(.debug, msg)
}

pub fn (l Logger) trace(msg string) {
	l.emit(.trace, msg)
}

// format_record renders a record as a single line, including the trailing
// newline. Sinks share it so output stays consistent across destinations.
pub fn format_record(level Level, scope string, msg string) string {
	mut sb := strings.new_builder(64 + msg.len)
	sb.write_string(time.now().format_rfc3339_micro())
	sb.write_string(' ')
	sb.write_string(level_label(level))
	sb.write_string(' ')
	if scope != '' {
		sb.write_string('[')
		sb.write_string(scope)
		sb.write_string('] ')
	}
	sb.write_string(msg)
	sb.write_string('\n')
	return sb.str()
}

fn level_label(level Level) string {
	return match level {
		.disabled { 'OFF  ' }
		.error { 'ERROR' }
		.warn { 'WARN ' }
		.info { 'INFO ' }
		.debug { 'DEBUG' }
		.trace { 'TRACE' }
	}
}

// NopSink discards every record.
pub struct NopSink {}

pub fn (s NopSink) write(level Level, scope string, msg string) {}

// StderrSink writes one line per record to standard error.
//
// Writes are serialised by a mutex: the stack logs from several threads and
// interleaved partial lines are worse than useless when debugging a
// connectivity failure.
pub struct StderrSink {
mut:
	mu &sync.Mutex = unsafe { nil }
}

// StderrSink.new returns a sink ready for concurrent use.
pub fn StderrSink.new() &StderrSink {
	return &StderrSink{
		mu: sync.new_mutex()
	}
}

pub fn (s &StderrSink) write(level Level, scope string, msg string) {
	line := format_record(level, scope, msg)
	if s.mu == unsafe { nil } {
		eprint(line)
		return
	}
	mut mu := s.mu
	mu.lock()
	eprint(line)
	mu.unlock()
}

// WriterSink sends records to any io.Writer, for applications that route logs
// into a file or an existing logging pipeline.
pub struct WriterSink {
mut:
	dest io.Writer
	mu   &sync.Mutex = unsafe { nil }
}