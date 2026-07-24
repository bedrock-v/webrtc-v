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