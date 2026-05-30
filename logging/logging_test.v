module logging

import sync

struct CaptureSink {
mut:
	mu      &sync.Mutex = sync.new_mutex()
	records []string
}

fn (s &CaptureSink) write(level Level, scope string, msg string) {
	mut m := unsafe { s }
	m.mu.lock()
	m.records << '${level}|${scope}|${msg}'
	m.mu.unlock()
}

fn (s &CaptureSink) snapshot() []string {
	mut m := unsafe { s }
	m.mu.lock()
	out := m.records.clone()
	m.mu.unlock()
	return out
}

fn test_level_ordering_filters_records() {
	sink := &CaptureSink{}
	log := new('test', .info, sink)

	log.trace('t')
	log.debug('d')
	log.info('i')
	log.warn('w')
	log.error('e')

	records := sink.snapshot()
	assert records.len == 3
	assert records[0] == 'info|test|i'
	assert records[1] == 'warn|test|w'
	assert records[2] == 'error|test|e'
}

fn test_disabled_logger_emits_nothing() {
	sink := &CaptureSink{}
	log := new('test', .disabled, sink)
	log.error('should not appear')
	assert sink.snapshot().len == 0
}

fn test_nop_logger_is_disabled() {
	log := nop()
	assert !log.enabled(.error)
	log.error('safe to call')
}

fn test_with_scope_nests_names() {
	sink := &CaptureSink{}
	log := new('ice', .debug, sink)
	child := log.with_scope('agent')
	grandchild := child.with_scope('pair')

	child.debug('a')
	grandchild.debug('b')

	records := sink.snapshot()
	assert records[0] == 'debug|ice.agent|a'
	assert records[1] == 'debug|ice.agent.pair|b'
}

fn test_with_scope_on_empty_scope() {
	log := nop().with_scope('root')
	assert log.scope == 'root'
}

fn test_with_level_returns_independent_copy() {
	sink := &CaptureSink{}
	log := new('x', .error, sink)
	verbose := log.with_level(.trace)

	log.debug('hidden')
	verbose.debug('shown')

	records := sink.snapshot()
	assert records.len == 1
	assert records[0] == 'debug|x|shown'
}

fn test_enabled_reports_threshold() {
	log := new('x', .warn, NopSink{})
	assert log.enabled(.error)
	assert log.enabled(.warn)
	assert !log.enabled(.info)
	assert !log.enabled(.debug)
}

fn test_level_string_round_trip() {
	levels := [Level.disabled, .error, .warn, .info, .debug, .trace]
	for level in levels {
		assert level_from_string(level.str())! == level
	}
	assert level_from_string('WARNING')! == Level.warn
	assert level_from_string(' Off ')! == Level.disabled
	level_from_string('nonsense') or { return }
	assert false, 'unknown level must be rejected'
}

fn test_format_record_shape() {
	line := format_record(.warn, 'ice', 'candidate failed')
	assert line.ends_with('\n')
	assert line.contains('WARN')
	assert line.contains('[ice]')
	assert line.contains('candidate failed')

	unscoped := format_record(.info, '', 'plain')
	assert !unscoped.contains('[]')
}

fn test_concurrent_logging_does_not_lose_records() {
	sink := &CaptureSink{}
	log := new('c', .info, sink)

	mut threads := []thread{}
	for i in 0 .. 8 {
		threads << spawn fn (l Logger, id int) {
			for j in 0 .. 32 {
				l.info('${id}-${j}')
			}
		}(log, i)
	}
	threads.wait()

	assert sink.snapshot().len == 8 * 32
}
