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

// build_record wraps one payload in a record, encrypting it if the current
// epoch is protected.
fn (mut c Conn) build_record(content_type ContentType, payload []u8) ![]u8 {
	sequence_number := c.send_sequence
	c.send_sequence++
	if c.send_sequence > 0xFFFFFFFFFFFF {
		// The 48-bit sequence number has wrapped. Continuing would repeat a GCM
		// nonce under the same key, which reveals the authentication key, so
		// the connection stops instead.
		return ConnError{
			reason: .wrong_state
			detail: 'the record sequence number space is exhausted; the connection must be re-keyed'
		}
	}

	mut fragment := payload.clone()
	if mut cipher := c.send_cipher {
		fragment = cipher.protect(c.send_epoch, sequence_number, content_type, .dtls_1_2, payload)!
		c.send_cipher = cipher
	}

	record := Record{
		content_type:    content_type
		version:         .dtls_1_2
		epoch:           c.send_epoch
		sequence_number: sequence_number
		fragment:        fragment
	}
	return record.marshal()!
}

// send_change_cipher_spec sends the one-byte message that switches the sending
// epoch, then installs the new keys.
//
// The order matters: the message itself must go out under the old epoch, and
// everything after it under the new one.
fn (mut c Conn) send_change_cipher_spec(cipher RecordCipher) ! {
	c.send_records(.change_cipher_spec, [[u8(1)]])!
	c.send_epoch++
	c.send_sequence = 0
	c.send_cipher = cipher
}

// send_alert sends a fatal alert. Failures are ignored: the connection is
// already being torn down, and there is nothing useful to do if the notice
// cannot be delivered.
fn (mut c Conn) send_alert(description u8) {
	c.send_records(.alert, [[alert_level_fatal, description]]) or {}
}

// receive_records reads one datagram and returns the records in it that are
// usable: correctly framed, in an epoch we have keys for, not replayed, and
// decrypted.
fn (mut c Conn) receive_records(timeout time.Duration) ![]Record {
	datagram := c.transport.recv(timeout) or {
		return ConnError{
			reason: .timed_out
			detail: err.msg()
		}
	}
	if !is_dtls(datagram) {
		// Something else on the transport. At this layer that is noise, not an
		// error worth failing the handshake over.
		return []Record{}
	}

	records := unmarshal_records(datagram) or {
		c.log.debug('discarded a malformed datagram: ${err.msg()}')
		return []Record{}
	}

	mut out := []Record{}
	for record in records {
		usable := c.accept_record(record) or {
			c.log.debug('discarded a record: ${err.msg()}')
			continue
		}
		out << usable
	}
	return out
}

// accept_record validates and decrypts one record.
fn (mut c Conn) accept_record(record Record) !Record {
	if record.epoch > c.recv_epoch {
		// A record from the next epoch, arriving before the peer's
		// ChangeCipherSpec. It cannot be decrypted yet, and buffering it would
		// let a peer make us hold arbitrary state, so it is dropped and left to
		// the peer's retransmission.
		return ConnError{
			reason: .wrong_state
			detail: 'record is from epoch ${record.epoch}, we are on ${c.recv_epoch}'
		}
	}
	if record.epoch < c.recv_epoch {
		return ConnError{
			reason: .wrong_state
			detail: 'record is from the superseded epoch ${record.epoch}'
		}
	}
	if !c.replay.check(record.sequence_number) {
		return ConnError{
			reason: .wrong_state
			detail: 'record ${record.sequence_number} has already been seen'
		}
	}

	mut plaintext := record.fragment.clone()
	if mut cipher := c.recv_cipher {
		plaintext = cipher.unprotect(record.epoch, record.sequence_number, record.content_type,
			record.version, record.fragment) or {
			// The replay window is deliberately not advanced here. Doing so
			// would let anyone who can reach the transport burn sequence
			// numbers the real peer is about to use.
			return ConnError{
				reason: .alert
				detail: err.msg()
			}
		}
		c.recv_cipher = cipher
	}

	// Only an authentic record advances the window.
	c.replay.accept(record.sequence_number)

	return Record{
		content_type:    record.content_type
		version:         record.version
		epoch:           record.epoch
		sequence_number: record.sequence_number
		fragment:        plaintext
	}
}

// handle_change_cipher_spec installs the receiving keys for the next epoch.
fn (mut c Conn) handle_change_cipher_spec(record Record, cipher RecordCipher) ! {
	if record.fragment.len != 1 || record.fragment[0] != 1 {
		return ConnError{
			reason: .handshake_failure
			detail: 'malformed ChangeCipherSpec'
		}
	}
	c.recv_epoch++
	c.recv_cipher = cipher
	// Sequence numbers restart in a new epoch, so the replay window must too.
	c.replay = AntiReplay.new(default_replay_window)
}

// handle_alert turns a received alert into an error, or into nothing when it is
// a warning we can ignore.
fn (mut c Conn) handle_alert(record Record) ! {
	if record.fragment.len < 2 {
		return ConnError{
			reason: .alert
			detail: 'truncated alert'
		}
	}
	level := record.fragment[0]
	description := record.fragment[1]
	name := alert_description_name(description)

	if description == alert_close_notify {
		c.state = .closed
		return ConnError{
			reason: .closed
			detail: 'the peer closed the connection'
		}
	}
	if level == alert_level_warning {
		c.log.debug('peer sent a warning alert: ${name}')
		return
	}
	c.state = .failed
	return ConnError{
		reason: .alert
		detail: 'peer sent a fatal alert: ${name}'
	}
}

// collect_handshake reassembles handshake fragments from a record and returns
// any messages that became complete, in message-sequence order.
//
// Out-of-order and duplicate fragments are both expected on a datagram
// transport: a retransmitted flight arrives alongside the original, and a
// message we have already processed must be ignored rather than reprocessed.
fn (mut c Conn) collect_handshake(record Record) ![]HandshakeMessage {
	fragments := unmarshal_handshake_fragments(record.fragment) or {
		return ConnError{
			reason: .handshake_failure
			detail: err.msg()
		}
	}

	for fragment in fragments {
		if fragment.header.message_seq < c.expected_message_seq {
			// Already processed. The peer repeating it means our answer did not
			// arrive, so the caller should send it again.
			c.saw_retransmission = true
			continue
		}
		if fragment.header.message_seq >= c.expected_message_seq + max_handshake_messages {
			return ConnError{
				reason: .handshake_failure
				detail: 'message sequence ${fragment.header.message_seq} is too far ahead of ${c.expected_message_seq}'
			}
		}

		mut pending := c.pending[fragment.header.message_seq] or {
			PendingMessage{
				typ:    fragment.header.typ
				length: fragment.header.length
				body:   []u8{len: int(fragment.header.length)}
			}
		}
		if pending.typ != fragment.header.typ || pending.length != fragment.header.length {
			return ConnError{
				reason: .handshake_failure
				detail: 'fragments of message ${fragment.header.message_seq} disagree about its type or length'
			}
		}
		pending.add(fragment.header.fragment_offset, fragment.body)
		c.pending[fragment.header.message_seq] = pending
	}

	// Deliver in order. A message that arrived early waits until its
	// predecessors have, because the transcript hash depends on the order.
	mut out := []HandshakeMessage{}
	for {
		pending := c.pending[c.expected_message_seq] or { break }
		if !pending.is_complete() {
			break
		}
		message := unmarshal_handshake_message(pending.typ, pending.body) or {
			return ConnError{
				reason: .handshake_failure
				detail: err.msg()
			}
		}
		// Snapshot the transcript before appending, for the two messages whose
		// contents are computed over everything that precedes them.
		match pending.typ {
			.certificate_verify { c.transcript_at_certificate_verify = c.transcript.clone() }
			.finished { c.transcript_at_peer_finished = c.transcript.clone() }
			else {}
		}
		// HelloVerifyRequest is excluded from the transcript by RFC 6347
		// section 4.2.1, along with the ClientHello that provoked it.
		if pending.typ != .hello_verify_request {
			c.append_transcript(pending.typ, c.expected_message_seq, pending.body)
		}
		c.log.trace('received ${pending.typ} (seq ${c.expected_message_seq}, ${pending.length} bytes)')
		out << message
		c.pending.delete(c.expected_message_seq)
		c.expected_message_seq++
	}
	return out
}