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

// -- Handshake encoding ----------------------------------------------------

fn test_handshake_fragmentation_and_reassembly() {
	body := []u8{len: 1000, init: u8(index)}
	fragments := fragment_message(.certificate, 7, body, 200)!
	assert fragments.len > 1

	mut pending := PendingMessage{
		typ:    .certificate
		length: u32(body.len)
		body:   []u8{len: body.len}
	}
	// Deliver the fragments in reverse, which is what a reordering path does.
	for i := fragments.len - 1; i >= 0; i-- {
		parsed := unmarshal_handshake_fragments(fragments[i])!
		assert parsed.len == 1
		assert parsed[0].header.message_seq == 7
		assert parsed[0].header.length == u32(body.len)
		pending.add(parsed[0].header.fragment_offset, parsed[0].body)
	}
	assert pending.is_complete()
	assert pending.body == body
}

fn test_duplicate_fragments_are_idempotent() {
	body := []u8{len: 300, init: u8(index)}
	fragments := fragment_message(.certificate, 1, body, 150)!

	mut pending := PendingMessage{
		typ:    .certificate
		length: u32(body.len)
		body:   []u8{len: body.len}
	}
	// A retransmitted flight delivers every fragment twice.
	for _ in 0 .. 2 {
		for fragment in fragments {
			parsed := unmarshal_handshake_fragments(fragment)!
			pending.add(parsed[0].header.fragment_offset, parsed[0].body)
		}
	}
	assert pending.is_complete()
	assert pending.body == body
}

fn test_zero_length_message_produces_one_fragment() {
	fragments := fragment_message(.server_hello_done, 5, []u8{}, 1200)!
	assert fragments.len == 1
	parsed := unmarshal_handshake_fragments(fragments[0])!
	assert parsed[0].header.length == 0
	assert parsed[0].header.is_complete()
}

fn test_handshake_fragment_rejects_overrun() {
	// A fragment claiming to extend past the message it belongs to.
	raw := hex.decode('0b000010000000000004000020')!
	unmarshal_handshake_fragments(raw) or { return }
	assert false, 'a fragment running past the message must be rejected'
}

fn test_client_hello_round_trip() {
	hello := ClientHello{
		random:        Random.generate()!
		cookie:        [u8(1), 2, 3]
		cipher_suites: [CipherSuite.ecdhe_ecdsa_with_aes_128_gcm_sha256]
		extensions:    [
			Extension(SupportedGroups{
				curves: [NamedCurve.secp256r1]
			}),
			Extension(UseSrtp{
				profiles: [srtp.Profile.aead_aes_128_gcm, .aes128_cm_hmac_sha1_80]
			}),
			Extension(ExtendedMasterSecret{}),
		]
	}
	body := HandshakeMessage(hello).marshal()!
	decoded := unmarshal_handshake_message(.client_hello, body)! as ClientHello

	assert decoded.random.bytes == hello.random.bytes
	assert decoded.cookie == [u8(1), 2, 3]
	assert decoded.cipher_suites == hello.cipher_suites
	assert decoded.extensions.len == 3

	srtp_extension := find_extension(decoded.extensions, ext_use_srtp)? as UseSrtp
	assert srtp_extension.profiles == [srtp.Profile.aead_aes_128_gcm, .aes128_cm_hmac_sha1_80]
	assert find_extension(decoded.extensions, ext_extended_master_secret) != none
}

fn test_server_hello_round_trip() {
	hello := ServerHello{
		random:       Random.generate()!
		cipher_suite: .ecdhe_ecdsa_with_aes_128_gcm_sha256
		extensions:   [
			Extension(UseSrtp{
				profiles: [srtp.Profile.aead_aes_128_gcm]
			}),
		]
	}
	body := HandshakeMessage(hello).marshal()!
	decoded := unmarshal_handshake_message(.server_hello, body)! as ServerHello
	assert decoded.cipher_suite == .ecdhe_ecdsa_with_aes_128_gcm_sha256
	assert decoded.random.bytes == hello.random.bytes
}

fn test_server_hello_rejects_compression() {
	// TLS compression is a vulnerability, not a feature.
	hello := ServerHello{
		random:             Random.generate()!
		cipher_suite:       .ecdhe_ecdsa_with_aes_128_gcm_sha256
		compression_method: 1
	}
	body := HandshakeMessage(hello).marshal()!
	unmarshal_handshake_message(.server_hello, body) or { return }
	assert false, 'a non-null compression method must be rejected'
}

fn test_certificate_message_round_trip() {
	first := []u8{len: 50, init: 1}
	second := []u8{len: 70, init: 2}
	message := CertificateMessage{
		certificates: [first, second]
	}
	body := HandshakeMessage(message).marshal()!
	decoded := unmarshal_handshake_message(.certificate, body)! as CertificateMessage
	assert decoded.certificates.len == 2
	assert decoded.certificates[0] == first
	assert decoded.certificates[1] == second
}

fn test_server_key_exchange_round_trip() {
	message := ServerKeyExchange{
		public_key: []u8{len: 65, init: u8(index)}
		signature:  []u8{len: 70, init: 9}
	}
	body := HandshakeMessage(message).marshal()!
	decoded := unmarshal_handshake_message(.server_key_exchange, body)! as ServerKeyExchange
	assert decoded.curve == .secp256r1
	assert decoded.public_key.len == 65
	assert decoded.signature.len == 70
	assert decoded.signature_hash == .sha256
}

fn test_finished_length_is_enforced() {
	unmarshal_handshake_message(.finished, []u8{len: 11}) or {
		unmarshal_handshake_message(.finished, []u8{len: 12})!
		return
	}
	assert false, 'a Finished of the wrong length must be rejected'
}

// -- Record protection -----------------------------------------------------

fn test_record_cipher_round_trip() {
	block := []u8{len: gcm_key_block_length, init: u8(index * 3 + 1)}
	keys := expand_key_block(block)!

	mut sender := RecordCipher.new(keys.client)!
	mut receiver := RecordCipher.new(keys.client)!

	plaintext := 'application data'.bytes()
	protected := sender.protect(1, 5, .application_data, .dtls_1_2, plaintext)!
	assert protected.len == plaintext.len + sender.overhead()

	recovered := receiver.unprotect(1, 5, .application_data, .dtls_1_2, protected)!
	assert recovered == plaintext
}

fn test_record_cipher_authenticates_the_header() {
	block := []u8{len: gcm_key_block_length, init: 7}
	keys := expand_key_block(block)!
	mut sender := RecordCipher.new(keys.server)!
	mut receiver := RecordCipher.new(keys.server)!

	protected := sender.protect(1, 5, .application_data, .dtls_1_2, 'x'.bytes())!

	// The header is associated data, so rewriting any of it must fail the tag.
	receiver.unprotect(2, 5, .application_data, .dtls_1_2, protected) or {
		receiver.unprotect(1, 6, .application_data, .dtls_1_2, protected) or {
			receiver.unprotect(1, 5, .handshake, .dtls_1_2, protected) or {
				// The untampered record still verifies.
				assert receiver.unprotect(1, 5, .application_data, .dtls_1_2, protected)! == 'x'.bytes()
				return
			}
			assert false, 'a rewritten content type must be detected'
		}
		assert false, 'a rewritten sequence number must be detected'
	}
	assert false, 'a rewritten epoch must be detected'
}

fn test_record_cipher_detects_tampering() {
	block := []u8{len: gcm_key_block_length, init: 3}
	keys := expand_key_block(block)!
	mut sender := RecordCipher.new(keys.client)!

	protected := sender.protect(1, 1, .application_data, .dtls_1_2, 'hello world'.bytes())!
	for i in 0 .. protected.len {
		mut tampered := protected.clone()
		tampered[i] ^= 0x01
		mut receiver := RecordCipher.new(keys.client)!
		receiver.unprotect(1, 1, .application_data, .dtls_1_2, tampered) or { continue }
		assert false, 'flipping byte ${i} was not detected'
	}
}

fn test_key_block_split_order() {
	// Both keys precede both IVs (RFC 5246 section 6.3).
	mut block := []u8{}
	block << []u8{len: 16, init: 0x11}
	block << []u8{len: 16, init: 0x22}
	block << []u8{len: 4, init: 0x33}
	block << []u8{len: 4, init: 0x44}

	keys := expand_key_block(block)!
	assert keys.client.key.all(it == 0x11)
	assert keys.server.key.all(it == 0x22)
	assert keys.client.fixed_iv.all(it == 0x33)
	assert keys.server.fixed_iv.all(it == 0x44)

	expand_key_block(block[..10]) or { return }
	assert false, 'a short key block must be rejected'
}

// -- Full handshake --------------------------------------------------------

struct HandshakePair {
mut:
	client &Conn
	server &Conn
}

fn run_handshake(client_config Config, server_config Config) !HandshakePair {
	mut client_pipe, mut server_pipe := new_pipe_pair()

	client_certificate := client_config.certificate or { Certificate.generate()! }
	server_certificate := server_config.certificate or { Certificate.generate()! }

	// Short timers so a broken handshake fails the test quickly instead of
	// sitting on the thirty-second default.
	mut client := Conn.new(client_pipe, Config{
		...client_config
		role:                .client
		certificate:         client_certificate
		handshake_timeout:   5 * time.second
		retransmit_interval: 50 * time.millisecond
		remote_fingerprints: if client_config.insecure_skip_fingerprint_verification {
			[]Fingerprint{}
		} else {
			[server_certificate.fingerprint(.sha256)]
		}
	})!
	mut server := Conn.new(server_pipe, Config{
		...server_config
		role:                .server
		certificate:         server_certificate
		handshake_timeout:   5 * time.second
		retransmit_interval: 50 * time.millisecond
		remote_fingerprints: if server_config.insecure_skip_fingerprint_verification {
			[]Fingerprint{}
		} else {
			[client_certificate.fingerprint(.sha256)]
		}
	})!

	server_thread := spawn fn (mut c Conn) ! {
		c.handshake()!
	}(mut server)
	client.handshake()!
	server_thread.wait()!

	return HandshakePair{
		client: client
		server: server
	}
}

fn test_full_handshake_over_a_pipe() {
	mut pair := run_handshake(Config{}, Config{})!

	assert pair.client.state() == .connected
	assert pair.server.state() == .connected
	assert pair.client.role() == .client
	assert pair.server.role() == .server

	// Each side learned the other's certificate.
	assert pair.client.remote_certificate() != none
	assert pair.server.remote_certificate() != none
}

fn test_handshake_negotiates_an_srtp_profile() {
	mut pair := run_handshake(Config{}, Config{})!

	client_profile := pair.client.selected_srtp_profile()?
	server_profile := pair.server.selected_srtp_profile()?
	assert client_profile == server_profile
	// Both sides list AES-GCM first, so that is what should win.
	assert client_profile == .aead_aes_128_gcm
}

fn test_srtp_keying_material_matches_on_both_sides() {
	mut pair := run_handshake(Config{}, Config{})!

	// The exporter output must be identical, or the two endpoints would key
	// SRTP differently and every packet would fail authentication.
	assert pair.client.srtp_keying_material()! == pair.server.srtp_keying_material()!
}

fn test_srtp_contexts_interoperate() {
	mut pair := run_handshake(Config{}, Config{})!

	mut client_out, mut client_in := pair.client.srtp_contexts()!
	mut server_out, mut server_in := pair.server.srtp_contexts()!

	// A packet the client protects must be the one the server can unprotect,
	// which is what checks that the client and server halves of the keying
	// material were assigned to the right directions.
	packet := [u8(0x80), 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xCA, 0xFE, 0xBA, 0xBE, 1, 2,
		3, 4]
	protected := client_out.protect_rtp(packet)!
	assert server_in.unprotect_rtp(protected)! == packet

	reply := server_out.protect_rtp(packet)!
	assert client_in.unprotect_rtp(reply)! == packet
}

fn test_srtp_profile_negotiation_picks_the_common_one() {
	// The client prefers AES-GCM; the server only speaks the counter-mode
	// profile, so that is what must be chosen.
	mut pair := run_handshake(Config{
		srtp_profiles: [srtp.Profile.aead_aes_128_gcm, .aes128_cm_hmac_sha1_80]
	}, Config{
		srtp_profiles: [srtp.Profile.aes128_cm_hmac_sha1_80]
	})!
	assert pair.client.selected_srtp_profile()? == .aes128_cm_hmac_sha1_80
	assert pair.server.selected_srtp_profile()? == .aes128_cm_hmac_sha1_80
}

fn test_application_data_flows_both_ways() {
	mut pair := run_handshake(Config{}, Config{})!

	message := 'hello over DTLS'.bytes()
	pair.client.write(message)!
	assert pair.server.read(5 * time.second)! == message

	reply := 'and back again'.bytes()
	pair.server.write(reply)!
	assert pair.client.read(5 * time.second)! == reply
}

fn test_message_boundaries_are_preserved() {
	mut pair := run_handshake(Config{}, Config{})!

	for i in 0 .. 5 {
		pair.client.write([]u8{len: 10 + i, init: u8(i)})!
	}
	for i in 0 .. 5 {
		received := pair.server.read(5 * time.second)!
		assert received.len == 10 + i
		assert received.all(it == u8(i))
	}
}

fn test_handshake_survives_packet_loss() {
	// Every flight is sent at least twice before anything gets through, which
	// is what the retransmission timer exists for.
	mut client_pipe, mut server_pipe := new_pipe_pair()

	client_certificate := Certificate.generate()!
	server_certificate := Certificate.generate()!

	mut client := Conn.new(client_pipe,
		role:                .client
		certificate:         client_certificate
		remote_fingerprints: [server_certificate.fingerprint(.sha256)]
		retransmit_interval: 50 * time.millisecond
	)!
	mut server := Conn.new(server_pipe,
		role:                .server
		certificate:         server_certificate
		remote_fingerprints: [client_certificate.fingerprint(.sha256)]
		retransmit_interval: 50 * time.millisecond
	)!

	// Drop the first datagram each side sends.
	client_pipe.drop(1)
	server_pipe.drop(1)

	server_thread := spawn fn (mut c Conn) ! {
		c.handshake()!
	}(mut server)
	client.handshake()!
	server_thread.wait()!

	assert client.state() == .connected
	assert server.state() == .connected
	assert client.srtp_keying_material()! == server.srtp_keying_material()!
}

fn test_handshake_fails_on_fingerprint_mismatch() {
	// The fingerprint is the only thing authenticating the peer. A certificate
	// that does not match what signalling said must be refused.
	mut client_pipe, mut server_pipe := new_pipe_pair()

	server_certificate := Certificate.generate()!
	impostor := Certificate.generate()!

	mut client := Conn.new(client_pipe,
		role:                .client
		remote_fingerprints: [impostor.fingerprint(.sha256)]
		handshake_timeout:   3 * time.second
		retransmit_interval: 50 * time.millisecond
	)!
	mut server := Conn.new(server_pipe,
		role:                                   .server
		certificate:                            server_certificate
		insecure_skip_fingerprint_verification: true
		handshake_timeout:                      3 * time.second
		retransmit_interval:                    50 * time.millisecond
	)!

	server_thread := spawn fn (mut c Conn) {
		c.handshake() or {}
	}(mut server)

	client.handshake() or {
		server_thread.wait()
		assert err is ConnError
		if err is ConnError {
			assert err.reason == .fingerprint_mismatch, 'got ${err.reason}'
		}
		assert client.state() == .failed
		return
	}
	server_thread.wait()
	assert false, 'a certificate that does not match the signalled fingerprint must be refused'
}

fn test_conn_requires_a_fingerprint_or_an_explicit_opt_out() {
	mut pipe, mut unused_peer := new_pipe_pair()
	// Leaving out the fingerprints without saying so removes the only peer
	// authentication there is, so it must be refused rather than silently
	// insecure.
	Conn.new(pipe, role: .client) or {
		assert err is ConnError
		mut other, mut other_peer := new_pipe_pair()
		Conn.new(other, role: .client, insecure_skip_fingerprint_verification: true)!
		return
	}
	assert false, 'a connection with no fingerprints and no opt-out must be refused'
}

fn test_handshake_cannot_be_run_twice() {
	mut pair := run_handshake(Config{}, Config{})!
	pair.client.handshake() or {
		assert err is ConnError
		if err is ConnError {
			assert err.reason == .wrong_state
		}
		return
	}
	assert false, 'a second handshake on the same connection must be refused'
}

fn test_read_and_write_before_the_handshake_are_refused() {
	mut pipe, mut unused_peer := new_pipe_pair()
	mut conn := Conn.new(pipe, role: .client, insecure_skip_fingerprint_verification: true)!

	conn.write('x'.bytes()) or {
		conn.read(10 * time.millisecond) or {
			assert err is ConnError
			return
		}
		assert false, 'reading before the handshake must be refused'
	}
	assert false, 'writing before the handshake must be refused'
}

fn test_write_refuses_oversized_messages() {
	mut pair := run_handshake(Config{}, Config{})!
	limit := pair.client.max_write()
	assert limit > 1000

	pair.client.write([]u8{len: limit})!
	pair.client.write([]u8{len: limit + 1}) or {
		assert err is ConnError
		return
	}
	assert false, 'a message larger than one record must be refused rather than split'
}

fn test_local_certificate_is_reported_for_signalling() {
	certificate := Certificate.generate()!
	mut pipe, mut unused_peer := new_pipe_pair()
	mut conn := Conn.new(pipe,
		role:                                   .client
		certificate:                            certificate
		insecure_skip_fingerprint_verification: true
	)!
	// The fingerprint an application must publish in its SDP.
	assert conn.local_certificate().fingerprint(.sha256).matches(certificate.fingerprint(.sha256))
}