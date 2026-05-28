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