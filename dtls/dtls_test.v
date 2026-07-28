module dtls

import encoding.hex
import sync
import time
import webrtc.srtp

// PipeTransport is an in-memory datagram channel between two connections.
//
// It models the properties of UDP that the handshake has to cope with: message
// boundaries are preserved, and datagrams can be dropped or reordered on
// demand, which is how the retransmission logic gets exercised.
struct PipeTransport {
mut:
	inbound chan []u8      = chan []u8{cap: 64}
	peer    &PipeTransport = unsafe { nil }
	mu      &sync.Mutex    = sync.new_mutex()
	// drop_next causes the next n sends to be discarded.
	drop_next int
	sent      int
	closed    bool
}

fn new_pipe_pair() (&PipeTransport, &PipeTransport) {
	mut a := &PipeTransport{}
	mut b := &PipeTransport{}
	a.peer = b
	b.peer = a
	return a, b
}

fn (mut p PipeTransport) send(data []u8) !int {
	p.mu.lock()
	if p.closed {
		p.mu.unlock()
		return error('pipe closed')
	}
	p.sent++
	drop := p.drop_next > 0
	if drop {
		p.drop_next--
	}
	p.mu.unlock()

	if drop {
		// Report success: a dropped datagram is indistinguishable from a
		// delivered one to the sender, which is the whole reason DTLS needs a
		// retransmission timer.
		return data.len
	}
	mut peer := p.peer
	// The payload is copied into a variable first. V 0.5.2 sends a zero value
	// when the expression in a select-send is a call, so `peer.inbound <-
	// data.clone()` would silently deliver an empty datagram.
	copy := data.clone()
	select {
		peer.inbound <- copy {}
		else {
			return error('peer queue full')
		}
	}
	return data.len
}

fn (mut p PipeTransport) recv(timeout time.Duration) ![]u8 {
	select {
		data := <-p.inbound {
			return data
		}
		timeout {
			return error('timeout')
		}
	}
	return error('closed')
}

fn (mut p PipeTransport) close() {
	p.mu.lock()
	p.closed = true
	p.mu.unlock()
}

fn (mut p PipeTransport) drop(n int) {
	p.mu.lock()
	p.drop_next = n
	p.mu.unlock()
}

// -- PRF -------------------------------------------------------------------

fn test_prf_is_deterministic_and_label_separated() {
	secret := 'secret'.bytes()
	seed := 'seed'.bytes()

	first := prf(secret, 'label', seed, 48)
	assert first.len == 48
	assert prf(secret, 'label', seed, 48) == first

	// A different label must give unrelated output; that separation is what
	// keeps the record keys, the Finished data and the SRTP material from being
	// derivable from each other.
	assert prf(secret, 'other', seed, 48) != first
	assert prf('other'.bytes(), 'label', seed, 48) != first
	assert prf(secret, 'label', 'other'.bytes(), 48) != first
}

fn test_prf_output_is_a_prefix_at_every_length() {
	// P_hash is an expanding chain, so a shorter request must be a prefix of a
	// longer one. If it is not, the block boundary handling is wrong.
	long := prf('k'.bytes(), 'l', 's'.bytes(), 100)
	for n in [1, 16, 31, 32, 33, 64, 99] {
		assert prf('k'.bytes(), 'l', 's'.bytes(), n) == long[..n]
	}
}

fn test_master_secret_length_and_ordering() {
	pre := []u8{len: 32, init: u8(index)}
	client := []u8{len: 32, init: 1}
	server := []u8{len: 32, init: 2}

	master := master_secret(pre, client, server)
	assert master.len == master_secret_length
	// The two randoms are not interchangeable; swapping them must change the
	// result, or two peers computing it in different orders would still agree
	// and the bug would hide until interop testing.
	assert master_secret(pre, server, client) != master
}

fn test_key_block_reverses_the_random_order() {
	master := []u8{len: 48, init: u8(index)}
	client := []u8{len: 32, init: 1}
	server := []u8{len: 32, init: 2}

	// RFC 5246 section 6.3 seeds the key expansion with server random first,
	// the opposite of the master secret derivation.
	block := key_block(master, client, server, 40)
	assert block.len == 40
	assert block != prf(master, 'key expansion', concat(client, server), 40)
	assert block == prf(master, 'key expansion', concat(server, client), 40)
}

fn concat(a []u8, b []u8) []u8 {
	mut out := []u8{cap: a.len + b.len}
	out << a
	out << b
	return out
}

fn test_verify_data_distinguishes_the_two_sides() {
	master := []u8{len: 48, init: 7}
	hash := []u8{len: 32, init: 3}

	client_side := verify_data(master, hash, true)
	server_side := verify_data(master, hash, false)
	assert client_side.len == verify_data_length
	// Different labels: a client must not be able to replay the server's
	// Finished back at it.
	assert client_side != server_side
}

fn test_srtp_keying_material_uses_the_exporter_label() {
	master := []u8{len: 48, init: 5}
	client := []u8{len: 32, init: 1}
	server := []u8{len: 32, init: 2}

	material := srtp_keying_material(master, client, server, 60)
	assert material.len == 60
	assert material == prf(master, 'EXTRACTOR-dtls_srtp', concat(client, server), 60)
	// It must be independent of the record keys derived from the same secret.
	assert material[..40] != key_block(master, client, server, 40)
}

// -- DER and certificates --------------------------------------------------

fn test_der_length_encoding() {
	assert der_length(0) == [u8(0)]
	assert der_length(127) == [u8(127)]
	assert der_length(128) == [u8(0x81), 128]
	assert der_length(255) == [u8(0x81), 255]
	assert der_length(256) == [u8(0x82), 1, 0]
	assert der_length(65535) == [u8(0x82), 0xff, 0xff]
}

fn test_der_integer_is_minimal_and_signed() {
	// Leading zeros are stripped, because DER requires the minimal encoding.
	assert der_integer_from_bytes([u8(0), 0, 1]) == [u8(2), 1, 1]
	// A value whose top bit is set needs a leading zero, or it would decode as
	// negative.
	assert der_integer_from_bytes([u8(0x80)]) == [u8(2), 2, 0, 0x80]
	assert der_integer_from_bytes([u8(0x7f)]) == [u8(2), 1, 0x7f]
	assert der_integer_from_bytes([]u8{}) == [u8(2), 1, 0]
}

fn test_der_oid_encoding() {
	// The first two arcs pack into one byte, and later arcs are base-128.
	assert der_oid('1.2.840.10045.2.1')!.hex() == '06072a8648ce3d0201'
	assert der_oid('2.5.4.3')!.hex() == '0603550403'
	der_oid('1') or { return }
}

fn test_der_oid_rejects_malformed() {
	for bad in ['', '1', '3.1.1', '1.40', 'a.b', '1.2.x'] {
		der_oid(bad) or { continue }
		assert false, 'expected "${bad}" to be rejected'
	}
}

fn test_der_parser_rejects_non_canonical_input() {
	cases := {
		'indefinite length':           '3080'
		'non-minimal long form':       '30810101'
		'long form for a short value': '30810f'
		'high tag number':             '1f0100'
		'truncated value':             '3005aabb'
		'leading zero length':         '308200ff'
	}
	for name, encoded in cases {
		raw := hex.decode(encoded)!
		der_parse(raw, 0) or { continue }
		assert false, 'expected ${name} to be rejected'
	}
}

fn test_certificate_generation_and_fingerprint() {
	certificate := Certificate.generate(common_name: 'test-cert')!
	assert certificate.der.len > 100

	// The fingerprint is over the DER, so it must be stable across calls and
	// differ between hashes.
	sha256_print := certificate.fingerprint(.sha256)
	assert sha256_print.algorithm == .sha256
	assert sha256_print.value.split(':').len == 32
	assert certificate.fingerprint(.sha256).matches(sha256_print)
	assert !certificate.fingerprint(.sha1).matches(sha256_print)
	assert certificate.fingerprint(.sha1).value.split(':').len == 20

	assert fingerprint_of(certificate.der, .sha256).matches(sha256_print)
}

fn test_certificates_are_distinct() {
	first := Certificate.generate()!
	second := Certificate.generate()!
	assert !first.fingerprint(.sha256).matches(second.fingerprint(.sha256))
}

fn test_certificate_round_trips_through_the_parser() {
	certificate := Certificate.generate(common_name: 'round-trip')!
	parsed := parse_certificate(certificate.der)!

	assert parsed.der == certificate.der
	assert parsed.not_before < parsed.not_after
	// The parsed public key must be the one that signed, which is checkable by
	// verifying something with it.
	message := 'proof of possession'.bytes()
	signature := certificate.private_key.sign(message)!
	assert parsed.public_key.verify(message, signature)!
}

fn test_certificate_parser_rejects_malformed_input() {
	certificate := Certificate.generate()!
	parse_certificate([]u8{}) or {
		parse_certificate(certificate.der[..20]) or {
			mut trailing := certificate.der.clone()
			trailing << 0x00
			parse_certificate(trailing) or { return }
			assert false, 'trailing bytes must be rejected'
		}
		assert false, 'a truncated certificate must be rejected'
	}
	assert false, 'empty input must be rejected'
}

fn test_fingerprint_parsing() {
	parsed := Fingerprint.parse('sha-256 AB:CD:EF:01')!
	assert parsed.algorithm == .sha256
	// Case is normalised, so a fingerprint from an SDP written in either case
	// compares equal to one we computed.
	assert parsed.value == 'ab:cd:ef:01'
	assert parsed.matches(Fingerprint.parse('SHA-256 ab:cd:ef:01')!)
	assert !parsed.matches(Fingerprint.parse('sha-1 ab:cd:ef:01')!)

	for bad in ['', 'sha-256', 'md5 aa:bb', 'sha-256 zz:xx', 'sha-256 aa bb'] {
		Fingerprint.parse(bad) or { continue }
		assert false, 'expected "${bad}" to be rejected'
	}
}

// -- Records ---------------------------------------------------------------

fn test_record_round_trip() {
	record := Record{
		content_type:    .handshake
		epoch:           3
		sequence_number: 0x0000AABBCCDD
		fragment:        [u8(1), 2, 3, 4]
	}
	raw := record.marshal()!
	assert raw.len == record_header_size + 4

	decoded := unmarshal_records(raw)!
	assert decoded.len == 1
	assert decoded[0].content_type == .handshake
	assert decoded[0].epoch == 3
	assert decoded[0].sequence_number == 0x0000AABBCCDD
	assert decoded[0].fragment == [u8(1), 2, 3, 4]
}

fn test_several_records_in_one_datagram() {
	mut datagram := []u8{}
	for i in 0 .. 3 {
		datagram << Record{
			content_type:    .handshake
			sequence_number: u64(i)
			fragment:        [u8(i)]
		}.marshal()!
	}
	decoded := unmarshal_records(datagram)!
	assert decoded.len == 3
	assert decoded[2].fragment == [u8(2)]
}

fn test_record_rejects_malformed_input() {
	cases := {
		'truncated header':     '16fefd0000'
		'unknown content type': '05fefd000000000000000000000000'
		'unknown version':      '16030300000000000000000000'
		'length past end':      '16fefd000000000000000000ff00'
	}
	for name, encoded in cases {
		raw := hex.decode(encoded)!
		unmarshal_records(raw) or { continue }
		assert false, 'expected ${name} to be rejected'
	}
}

fn test_record_sequence_number_is_48_bits() {
	record := Record{
		sequence_number: 0x1000000000000
	}
	record.marshal() or { return }
	assert false, 'a sequence number over 48 bits must be rejected'
}

fn test_is_dtls_demultiplexing() {
	record := Record{
		content_type: .handshake
		fragment:     []u8{len: 4}
	}
	assert is_dtls(record.marshal()!)

	// RFC 7983 gives DTLS the first-byte range 20 to 63.
	assert !is_dtls([]u8{len: 20, init: 0x00}) // STUN
	assert !is_dtls([]u8{len: 20, init: 0x80}) // RTP
	assert !is_dtls([]u8{len: 20, init: 0x40}) // TURN channel
	assert !is_dtls([]u8{len: 4, init: 0x16}) // too short
}

fn test_anti_replay_window() {
	mut window := AntiReplay.new(64)
	assert window.check(100)
	window.accept(100)
	assert !window.check(100)
	assert window.check(101)
	assert window.check(99)
	window.accept(99)
	assert !window.check(99)
	// Older than the window cannot be judged, so it is refused.
	assert !window.check(36)
	window.accept(1000)
	assert !window.check(100)
	assert window.highest_sequence_number() == 1000
}