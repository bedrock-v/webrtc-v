module dtls

import time

// Record input and output for a connection.
//
// Everything the handshake and the application send goes through send_records,
// and everything received goes through receive_records. Keeping both in one
// place is what makes the epoch and sequence-number bookkeeping - the part that
// is fatal to get wrong, because a repeated nonce breaks GCM completely -
// checkable by reading a single file.

// alert_level_fatal and the alert descriptions this implementation sends or
// recognises (RFC 5246 section 7.2).
const alert_level_warning = u8(1)
const alert_level_fatal = u8(2)

const alert_close_notify = u8(0)
const alert_unexpected_message = u8(10)
const alert_bad_record_mac = u8(20)
const alert_handshake_failure = u8(40)
const alert_bad_certificate = u8(42)
const alert_certificate_unknown = u8(46)
const alert_illegal_parameter = u8(47)
const alert_decrypt_error = u8(51)
const alert_internal_error = u8(80)

fn alert_description_name(code u8) string {
	return match code {
		alert_close_notify { 'close_notify' }
		alert_unexpected_message { 'unexpected_message' }
		alert_bad_record_mac { 'bad_record_mac' }
		alert_handshake_failure { 'handshake_failure' }
		alert_bad_certificate { 'bad_certificate' }
		alert_certificate_unknown { 'certificate_unknown' }
		alert_illegal_parameter { 'illegal_parameter' }
		alert_decrypt_error { 'decrypt_error' }
		alert_internal_error { 'internal_error' }
		else { 'alert ${code}' }
	}
}

// max_record_payload_for returns how many plaintext bytes fit one record at the
// configured MTU, after the record header and any AEAD overhead.
fn (c &Conn) max_record_payload() int {
	mut budget := c.config.mtu - record_header_size
	if cipher := c.send_cipher {
		budget -= cipher.overhead()
	}
	if budget < 1 {
		return 1
	}
	return budget
}

// send_records packs fragments into records and sends them, coalescing as many
// as fit one datagram.
//
// Coalescing matters for the handshake: a server's flight is four messages, and
// sending them in one datagram rather than four means one round of loss costs
// one retransmission instead of four.
fn (mut c Conn) send_records(content_type ContentType, fragments [][]u8) ! {
	mut datagram := []u8{}

	for fragment in fragments {
		record := c.build_record(content_type, fragment)!
		// Flush before exceeding the MTU, but never split a record: a record is
		// the unit the peer's parser works in.
		if datagram.len > 0 && datagram.len + record.len > c.config.mtu {
			c.transport.send(datagram) or {
				return ConnError{
					reason: .transport
					detail: 'sending a datagram: ${err.msg()}'
				}
			}
			datagram = []u8{}
		}
		datagram << record
	}

	if datagram.len > 0 {
		c.transport.send(datagram) or {
			return ConnError{
				reason: .transport
				detail: 'sending a datagram: ${err.msg()}'
			}
		}
	}
}