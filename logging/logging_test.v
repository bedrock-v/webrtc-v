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