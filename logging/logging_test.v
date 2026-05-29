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