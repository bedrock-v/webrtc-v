module datachannel

import time
import webrtc.sctp

// Sending and receiving on a channel, and the routing loop that feeds it.

// send_text sends a string message.
pub fn (mut c Channel) send_text(text string) ! {
	c.send(text.bytes(), true)!
}

// send_binary sends a binary message.
pub fn (mut c Channel) send_binary(data []u8) ! {
	c.send(data, false)!
}

// send delivers a message on the channel.
//
// The payload protocol identifier is what carries the string-or-binary
// distinction, not the bytes, which is why an empty string and empty binary
// data stay distinguishable. RFC 8831 gives each an identifier of its own for
// exactly that reason.
pub fn (mut c Channel) send(data []u8, is_string bool) ! {
	c.mu.lock()
	state := c.state
	mut manager := c.manager
	c.mu.unlock()

	if state != .open {
		return ChannelError{
			reason: .wrong_state
			detail: 'the channel is ${state}, not open'
		}
	}
	if manager == unsafe { nil } {
		return ChannelError{
			reason: .closed
			detail: 'the channel is detached from its manager'
		}
	}

	ppid := if data.len == 0 {
		if is_string { sctp.ppid_string_empty } else { sctp.ppid_binary_empty }
	} else if is_string {
		sctp.ppid_string
	} else {
		sctp.ppid_binary
	}

	manager.association.send(c.stream_identifier, ppid, data, c.channel_type.is_ordered()) or {
		if err is sctp.AssociationError && err.reason == .too_large {
			return ChannelError{
				reason: .too_large
				detail: err.detail
			}
		}
		return ChannelError{
			reason: .closed
			detail: err.msg()
		}
	}
}

// recv returns the next message, waiting up to timeout.
pub fn (mut c Channel) recv(timeout time.Duration) !Message {
	select {
		message := <-c.inbound {
			return message
		}
		timeout {
			if c.state() == .closed {
				return ChannelError{
					reason: .closed
					detail: 'the channel is closed'
				}
			}
			return ChannelError{
				reason: .timed_out
				detail: 'no message within ${timeout.milliseconds()}ms'
			}
		}
	}
	return ChannelError{
		reason: .closed
		detail: 'the channel is closed'
	}
}

// try_recv returns a message if one is already queued.
pub fn (mut c Channel) try_recv() ?Message {
	select {
		message := <-c.inbound {
			return message
		}
		else {
			return none
		}
	}
	return none
}

// close marks the channel closed and releases its stream identifier.
//
// It does not tear down the SCTP stream: doing that properly needs the stream
// reset of RFC 6525, which is on the roadmap. Until then the identifier is not
// reused within the association, which is what keeps a closed channel's late
// messages from being delivered to a new one.
pub fn (mut c Channel) close() {
	c.mu.lock()
	if c.state == .closed {
		c.mu.unlock()
		return
	}
	c.state = .closed
	c.mu.unlock()
	c.inbound.close()
}

fn (mut c Channel) mark_open() {
	c.mu.lock()
	if c.state == .connecting {
		c.state = .open
	}
	c.mu.unlock()
}

fn (mut c Channel) mark_closed() {
	c.mu.lock()
	if c.state == .closed {
		c.mu.unlock()
		return
	}
	c.state = .closed
	c.mu.unlock()
	c.inbound.close()
}

fn (mut c Channel) deliver(message Message) bool {
	if c.state() != .open {
		return false
	}
	select {
		c.inbound <- message {
			return true
		}
		else {
			return false
		}
	}
	return false
}

// run is the routing loop: it reads the association and dispatches what
// arrives to the right channel.
fn (mut m Manager) run() {
	for {
		if m.is_closed() {
			return
		}
		message := m.association.recv(50 * time.millisecond) or {
			if err is sctp.AssociationError && err.reason == .timed_out {
				continue
			}
			// The association is gone. Every channel on it is finished.
			m.log.debug('association ended: ${err.msg()}')
			m.shut_all_channels()
			return
		}
		m.route(message)
	}
}

// route dispatches one SCTP message.
fn (mut m Manager) route(message sctp.Message) {
	if message.payload_protocol_identifier == sctp.ppid_dcep {
		m.handle_dcep(message)
		return
	}

	m.mu.lock()
	mut channel := m.channels[message.stream_identifier] or {
		m.mu.unlock()
		// Data for a stream with no channel. A peer that opens a channel and
		// sends on it in the same flight can produce this legitimately when the
		// OPEN is still being processed; there is nothing useful to do but drop
		// it, and the channel's reliability guarantees do not extend to before
		// it existed.
		m.log.debug('dropped ${message.data.len} bytes for stream ${message.stream_identifier}, which has no channel')
		return
	}
	m.mu.unlock()

	is_string := message.payload_protocol_identifier == sctp.ppid_string
		|| message.payload_protocol_identifier == sctp.ppid_string_empty
		|| message.payload_protocol_identifier == sctp.ppid_string_partial
	// An empty message is carried as one padding byte under its own identifier,
	// so the byte is dropped here and the application sees the empty message it
	// was sent.
	empty := message.payload_protocol_identifier == sctp.ppid_string_empty
		|| message.payload_protocol_identifier == sctp.ppid_binary_empty
	data := if empty { []u8{} } else { message.data }

	if !channel.deliver(Message{ is_string: is_string, data: data }) {
		m.log.warn('channel on stream ${message.stream_identifier} is not accepting messages; dropped ${data.len} bytes')
	}
}