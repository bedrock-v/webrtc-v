module dtls

import time
import webrtc.internal.randutil

// The handshake driver.
//
// Both sides are written as an explicit sequence of flights rather than as a
// table-driven state machine. DTLS has six flights and they run in one order;
// spelling them out keeps each side readable against RFC 6347 section 4.2.4,
// and keeps the retransmission - which is the part that actually needs care on
// a lossy transport - visible at each step.

// handshake runs the handshake to completion.
//
// It blocks. On return the connection is either connected or failed, and a
// failed connection is not retryable: the ephemeral keys and the transcript
// belong to the attempt that failed.
pub fn (mut c Conn) handshake() ! {
	if c.state != .new {
		return ConnError{
			reason: .wrong_state
			detail: 'handshake has already been attempted; this connection is ${c.state}'
		}
	}
	c.state = .handshaking
	deadline := time.now().add(c.config.handshake_timeout)

	if c.is_client {
		c.run_client(deadline) or {
			c.state = .failed
			return err
		}
	} else {
		c.run_server(deadline) or {
			c.state = .failed
			return err
		}
	}

	c.state = .connected
	c.log.info('handshake complete as ${c.role()}${c.srtp_note()}')
}

fn (c &Conn) srtp_note() string {
	profile := c.negotiated_srtp_profile or { return '' }
	return ', SRTP profile ${profile}'
}

// flight holds the records of one flight, so it can be retransmitted verbatim.
//
// Retransmitting the same records rather than rebuilding them matters: a
// rebuilt flight would consume new record sequence numbers, and a peer that
// received the original would see two different records claiming to be the same
// handshake message.
struct Flight {
mut:
	handshake_records [][]u8
	// trailing carries the ChangeCipherSpec and Finished, which are sent after
	// the handshake records and under a different epoch.
	send_change_cipher_spec bool
	finished_records        [][]u8
}

// transmit sends a flight.
fn (mut c Conn) transmit(flight Flight, cipher ?RecordCipher) ! {
	if flight.handshake_records.len > 0 {
		c.send_records(.handshake, flight.handshake_records)!
	}
	if flight.send_change_cipher_spec {
		installed := cipher or {
			return ConnError{
				reason: .handshake_failure
				detail: 'a ChangeCipherSpec was queued with no cipher to install'
			}
		}

		c.send_change_cipher_spec(installed)!
	}
	if flight.finished_records.len > 0 {
		c.send_records(.handshake, flight.finished_records)!
	}
}

// retransmit_flight resends the records of a flight without advancing any
// handshake state.
fn (mut c Conn) retransmit_flight(flight Flight) ! {
	if flight.handshake_records.len > 0 {
		c.send_records(.handshake, flight.handshake_records)!
	}
	if flight.send_change_cipher_spec {
		// The ChangeCipherSpec belongs to the previous epoch, which we have
		// already left. Resending it is not possible without rewinding the
		// epoch, so the Finished alone is retransmitted; a peer that missed the
		// ChangeCipherSpec will retransmit its own flight and we will answer
		// again.
		c.log.debug('retransmitting the Finished without the ChangeCipherSpec')
	}
	if flight.finished_records.len > 0 {
		c.send_records(.handshake, flight.finished_records)!
	}
}

// run_client drives flights 1, 3 and 5.
fn (mut c Conn) run_client(deadline time.Time) ! {
	// Flight 1: ClientHello with no cookie.
	mut hello := c.build_client_hello([]u8{})!
	mut flight := Flight{
		handshake_records: c.queue_handshake(hello)!
	}
	c.transmit(flight, none)!

	// Flights 2 and 4: the server answers with either a HelloVerifyRequest, in
	// which case the hello is repeated with the cookie, or with its own flight.
	mut server_hello_done := false
	mut interval := c.config.retransmit_interval
	for !server_hello_done {
		if time.now() >= deadline {
			return ConnError{
				reason: .timed_out
				detail: 'the server did not complete its flight'
			}
		}
		c.saw_retransmission = false
		records := c.receive_records(interval) or {
			c.log.debug('retransmitting the client flight')
			c.retransmit_flight(flight)!
			interval = double_capped(interval)
			continue
		}
		for record in records {
			match record.content_type {
				.alert {
					c.handle_alert(record)!
				}
				.handshake {
					for message in c.collect_handshake(record)! {
						if message is HelloVerifyRequest {
							// Start the transcript again: RFC 6347 section
							// 4.2.1 excludes both the first ClientHello and the
							// HelloVerifyRequest from the hash.
							c.transcript = []u8{}
							c.cookie = message.cookie.clone()
							hello = c.build_client_hello(c.cookie)!
							flight = Flight{
								handshake_records: c.queue_handshake(hello)!
							}
							c.transmit(flight, none)!
							interval = c.config.retransmit_interval
							continue
						}
						if c.apply_server_message(message)! {
							server_hello_done = true
						}
					}
				}
				else {
					c.log.debug('ignoring a ${record.content_type} record during the handshake')
				}
			}
		}
		if c.saw_retransmission && !server_hello_done {
			// RFC 6347 section 4.2.4: the peer repeating a flight means ours did
			// not arrive, so it goes out again now rather than on the next timer
			// expiry.
			c.log.debug('the server repeated its flight; resending ours')
			c.retransmit_flight(flight)!
		}
	}

	// Flight 5: our certificate, key share, proof of possession and Finished.
	mut records := [][]u8{}
	records << c.queue_handshake(CertificateMessage{
		certificates: [c.local_certificate.der]
	})!
	records << c.queue_handshake(ClientKeyExchange{
		public_key: c.local_ecdh_point()!
	})!

	// RFC 7627 defines the session hash as covering the handshake up to and
	// including the ClientKeyExchange, so the master secret is derived exactly
	// here - after the key share is in the transcript and before the
	// CertificateVerify is. Deriving it anywhere else gives a hash the peer
	// will not reproduce.
	c.derive_secrets()!
	keys := c.record_keys()!

	records << c.queue_handshake(c.build_certificate_verify()!)!

	// The Finished is computed over everything above, so it is built after the
	// rest have been added to the transcript.
	finished := Finished{
		verify_data: verify_data(c.master_secret, c.transcript_hash(), true)
	}
	send_cipher := RecordCipher.new(keys.client)!
	recv_cipher := RecordCipher.new(keys.server)!

	finished_records := c.queue_handshake(finished)!
	// The server's Finished is computed over the transcript including ours,
	// which queue_handshake has just appended.
	expected_peer_verify := verify_data(c.master_secret, c.transcript_hash(), false)

	flight = Flight{
		handshake_records:       records
		send_change_cipher_spec: true
		finished_records:        finished_records
	}
	c.transmit(flight, send_cipher)!

	c.await_peer_finished(flight, recv_cipher, expected_peer_verify, deadline)!
}

// run_server drives flights 2, 4 and 6.
fn (mut c Conn) run_server(deadline time.Time) ! {
	// Flight 1: wait for a ClientHello.
	mut client_hello := c.await_client_hello(deadline, Flight{})!

	// Flight 2: answer an uncookied hello with a HelloVerifyRequest.
	//
	// This is what keeps a spoofed ClientHello from making us allocate state and
	// send a much larger flight to a forged address. ICE has already proven the
	// peer can receive at its address, so the protection is partly redundant
	// here, but a browser expects it and it costs one small datagram.
	if client_hello.cookie.len == 0 {
		c.cookie = randutil.bytes(20)!
		verify := HelloVerifyRequest{
			cookie: c.cookie
		}
		records := c.queue_handshake(verify)!
		// Neither the first ClientHello nor the HelloVerifyRequest is part of
		// the hash.
		c.transcript = []u8{}
		verify_flight := Flight{
			handshake_records: records
		}
		c.transmit(verify_flight, none)!

		client_hello = c.await_client_hello(deadline, verify_flight)!
		if client_hello.cookie != c.cookie {
			c.send_alert(alert_illegal_parameter)
			return ConnError{
				reason: .handshake_failure
				detail: 'the second ClientHello carried the wrong cookie'
			}
		}
	}

	c.remote_random = client_hello.random
	c.select_parameters(client_hello)!

	// Flight 4: our parameters, certificate, key share and a request for theirs.
	mut records := [][]u8{}
	records << c.queue_handshake(c.build_server_hello()!)!
	records << c.queue_handshake(CertificateMessage{
		certificates: [c.local_certificate.der]
	})!
	records << c.queue_handshake(c.build_server_key_exchange()!)!
	records << c.queue_handshake(CertificateRequest{})!
	records << c.queue_handshake(ServerHelloDone{})!

	mut flight := Flight{
		handshake_records: records
	}
	c.transmit(flight, none)!

	// Flight 5: the client's certificate, key share, proof and Finished.
	mut peer_finished := ?Finished(none)
	mut interval := c.config.retransmit_interval
	for {
		if time.now() >= deadline {
			return ConnError{
				reason: .timed_out
				detail: 'the client did not complete its flight'
			}
		}
		c.saw_retransmission = false
		records_in := c.receive_records(interval) or {
			c.log.debug('retransmitting the server flight')
			c.retransmit_flight(flight)!
			interval = double_capped(interval)
			continue
		}
		mut done := false
		for record in records_in {
			match record.content_type {
				.alert {
					c.handle_alert(record)!
				}
				.change_cipher_spec {
					// The master secret was derived when the ClientKeyExchange
					// arrived, at the transcript point RFC 7627 requires.
					keys := c.record_keys()!
					c.handle_change_cipher_spec(record, RecordCipher.new(keys.client)!)!
				}
				.handshake {
					for message in c.collect_handshake(record)! {
						if message is Finished {
							peer_finished = message
							done = true
							continue
						}
						c.apply_client_message(message)!
					}
				}
				else {
					c.log.debug('ignoring a ${record.content_type} record during the handshake')
				}
			}
		}
		if done {
			break
		}
		if c.saw_retransmission {
			c.log.debug('the client repeated its flight; resending ours')
			c.retransmit_flight(flight)!
		}
	}

	received := peer_finished or {
		return ConnError{
			reason: .handshake_failure
			detail: 'the client flight ended without a Finished'
		}
	}

	expected :=
		verify_data(c.master_secret, transcript_hash_of(c.transcript_at_peer_finished), true)
	if !constant_time_equal(received.verify_data, expected) {
		c.send_alert(alert_decrypt_error)
		return ConnError{
			reason: .bad_signature
			detail: 'the client Finished did not verify'
		}
	}

	// Flight 6: our own ChangeCipherSpec and Finished.
	keys := c.record_keys()!
	finished := Finished{
		verify_data: verify_data(c.master_secret, c.transcript_hash(), false)
	}
	finished_records := c.queue_handshake(finished)!
	c.transmit(Flight{
		send_change_cipher_spec: true
		finished_records:        finished_records
	}, RecordCipher.new(keys.server)!)!
}

// await_client_hello waits for a ClientHello.
//
// The flight argument is what to resend if the client repeats itself, which
// means our answer to its previous hello was lost. On the very first call there
// is nothing to resend and the flight is empty.
fn (mut c Conn) await_client_hello(deadline time.Time, flight Flight) !ClientHello {
	mut interval := c.config.retransmit_interval
	for {
		if time.now() >= deadline {
			return ConnError{
				reason: .timed_out
				detail: 'no ClientHello arrived'
			}
		}
		c.saw_retransmission = false
		records := c.receive_records(interval) or {
			if flight.handshake_records.len > 0 {
				c.log.debug('retransmitting the HelloVerifyRequest')
				c.retransmit_flight(flight)!
				interval = double_capped(interval)
			}
			continue
		}
		for record in records {
			match record.content_type {
				.alert {
					c.handle_alert(record)!
				}
				.handshake {
					for message in c.collect_handshake(record)! {
						if message is ClientHello {
							return message
						}
						return ConnError{
							reason: .handshake_failure
							detail: 'expected a ClientHello, got a ${message.handshake_type()}'
						}
					}
				}
				else {}
			}
		}
		if c.saw_retransmission && flight.handshake_records.len > 0 {
			c.log.debug('client repeated its hello; resending the HelloVerifyRequest')
			c.retransmit_flight(flight)!
		}
	}
	return ConnError{
		reason: .timed_out
		detail: 'no ClientHello arrived'
	}
}

// await_peer_finished waits for the peer's ChangeCipherSpec and Finished.
fn (mut c Conn) await_peer_finished(flight Flight, recv_cipher RecordCipher, expected []u8, deadline time.Time) ! {
	mut interval := c.config.retransmit_interval
	for {
		if time.now() >= deadline {
			return ConnError{
				reason: .timed_out
				detail: 'the peer did not send a Finished'
			}
		}
		c.saw_retransmission = false
		records := c.receive_records(interval) or {
			c.log.debug('retransmitting the final flight')
			c.retransmit_flight(flight)!
			interval = double_capped(interval)
			continue
		}
		for record in records {
			match record.content_type {
				.alert {
					c.handle_alert(record)!
				}
				.change_cipher_spec {
					c.handle_change_cipher_spec(record, recv_cipher)!
				}
				.handshake {
					for message in c.collect_handshake(record)! {
						if message is Finished {
							if !constant_time_equal(message.verify_data, expected) {
								c.send_alert(alert_decrypt_error)
								return ConnError{
									reason: .bad_signature
									detail: 'the peer Finished did not verify'
								}
							}
							return
						}
						c.log.debug('ignoring a ${message.handshake_type()} while waiting for Finished')
					}
				}
				.application_data {
					// The peer's first data can share a datagram with its
					// Finished. Hold it rather than dropping it; the caller
					// will ask for it in a moment.
					c.buffered << record.fragment
				}
			}
		}
		if c.saw_retransmission {
			c.log.debug('the peer repeated its flight; resending ours')
			c.retransmit_flight(flight)!
		}
	}
}

fn double_capped(interval time.Duration) time.Duration {
	doubled := interval * 2
	// RFC 6347 section 4.2.4.1 caps the retransmission timer at 60 seconds.
	if doubled > 60 * time.second {
		return 60 * time.second
	}
	return doubled
}

// constant_time_equal compares two byte strings without an early exit.
//
// Verify data is a secret in the sense that matters here: a comparison that
// stops at the first differing byte would tell an attacker how much of a
// guessed value was right.
fn constant_time_equal(a []u8, b []u8) bool {
	if a.len != b.len {
		return false
	}
	mut difference := u8(0)
	for i in 0 .. a.len {
		difference |= a[i] ^ b[i]
	}
	return difference == 0
}
