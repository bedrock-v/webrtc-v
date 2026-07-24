module dtls

import time

// Application data over an established connection.

// write sends application data.
//
// A datagram protocol preserves message boundaries, and so does this: one call
// produces one record, and the peer's read returns exactly what was written.
// Data larger than one record is refused rather than silently split, because
// splitting would break that guarantee for a caller that is relying on it -
// SCTP above this layer is.
pub fn (mut c Conn) write(data []u8) !int {
	if c.state != .connected {
		return ConnError{
			reason: .wrong_state
			detail: 'the connection is ${c.state}, not connected'
		}
	}
	limit := c.max_record_payload()
	if data.len > limit {
		return ConnError{
			reason: .wrong_state
			detail: '${data.len} bytes exceeds the ${limit}-byte record payload at this MTU'
		}
	}
	c.send_records(.application_data, [data])!
	return data.len
}

// read returns the next application message, waiting up to timeout.
//
// Records that are not application data are handled here rather than returned:
// a retransmitted Finished from a peer that missed ours is answered by ignoring
// it, and an alert becomes an error.
pub fn (mut c Conn) read(timeout time.Duration) ![]u8 {
	if c.buffered.len > 0 {
		out := c.buffered[0]
		c.buffered.delete(0)
		return out
	}
	if c.state != .connected {
		return ConnError{
			reason: .wrong_state
			detail: 'the connection is ${c.state}, not connected'
		}
	}

	deadline := time.now().add(timeout)
	for {
		remaining := deadline - time.now()
		if remaining <= 0 {
			return ConnError{
				reason: .timed_out
				detail: 'no application data within ${timeout.milliseconds()}ms'
			}
		}
		records := c.receive_records(remaining) or {
			if err is ConnError && err.reason == .timed_out {
				continue
			}
			return err
		}
		for record in records {
			match record.content_type {
				.application_data {
					if record.fragment.len > 0 {
						c.buffered << record.fragment
					}
				}
				.alert {
					c.handle_alert(record)!
				}
				.handshake {
					// A peer whose final flight was lost retransmits it. There
					// is nothing to do: our own Finished has already been sent,
					// and re-processing the message would corrupt the
					// transcript.
					c.log.debug('ignoring a retransmitted handshake record')
				}
				.change_cipher_spec {
					c.log.debug('ignoring a retransmitted ChangeCipherSpec')
				}
			}
		}
		if c.buffered.len > 0 {
			out := c.buffered[0]
			c.buffered.delete(0)
			return out
		}
	}
	return ConnError{
		reason: .timed_out
		detail: 'no application data'
	}
}