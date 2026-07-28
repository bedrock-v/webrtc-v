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