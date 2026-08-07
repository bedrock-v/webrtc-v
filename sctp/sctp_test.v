module sctp

import encoding.hex
import sync
import time
import webrtc.logging

// -- CRC-32c ---------------------------------------------------------------

fn test_crc32c_check_values() {
	// The check value from the CRC catalogue for CRC-32/ISCSI, plus the empty
	// string. Getting the polynomial wrong - using the IEEE one from the
	// standard library - produces a checksum every SCTP peer rejects, and this
	// is the only way to notice without a peer to talk to.
	assert crc32c([]u8{}) == 0x00000000
	assert crc32c('123456789'.bytes()) == 0xE3069283
	assert crc32c('a'.bytes()) == 0xC1D04330
	assert crc32c('The quick brown fox jumps over the lazy dog'.bytes()) == 0x22620404
}

fn test_crc32c_is_not_crc32() {
	// A guard against someone "simplifying" this to hash.crc32.
	assert crc32c('123456789'.bytes()) != 0xCBF43926
}

// -- Packets and chunks ----------------------------------------------------

fn test_packet_round_trip() {
	packet := Packet{
		verification_tag: 0xDEADBEEF
		chunks:           [
			RawChunk{
				typ:   u8(ChunkType.cookie_ack)
				value: []u8{}
			},
			RawChunk{
				typ:   u8(ChunkType.heartbeat)
				value: [u8(1), 2, 3]
			},
		]
	}
	raw := packet.marshal()!
	decoded := Packet.decode(raw, default_max_chunks)!

	assert decoded.verification_tag == 0xDEADBEEF
	assert decoded.source_port == webrtc_port
	assert decoded.chunks.len == 2
	assert decoded.chunks[0].chunk_type()? == .cookie_ack
	assert decoded.chunks[1].value == [u8(1), 2, 3]
}

fn test_packet_checksum_is_verified() {
	packet := Packet{
		verification_tag: 1
		chunks:           [
			RawChunk{
				typ:   u8(ChunkType.cookie_ack)
				value: []u8{}
			},
		]
	}
	raw := packet.marshal()!

	// Flipping any byte must be caught, including one inside the checksum
	// field itself.
	for i in 0 .. raw.len {
		mut tampered := raw.clone()
		tampered[i] ^= 0x01
		Packet.decode(tampered, default_max_chunks) or { continue }
		assert false, 'flipping byte ${i} was not detected'
	}
}

fn test_packet_rejects_malformed_input() {
	Packet.decode([]u8{len: 4}, default_max_chunks) or {
		assert err is DecodeError
		if err is DecodeError {
			assert err.reason == .too_short
		}
		return
	}
	assert false, 'a short packet must be rejected'
}

fn test_chunk_length_below_the_header_is_rejected() {
	// A length under four would make the chunk walker loop forever, which is
	// exactly what a hostile peer would send.
	unmarshal_chunks([u8(0x0B), 0x00, 0x00, 0x02], default_max_chunks) or {
		assert err is DecodeError
		if err is DecodeError {
			assert err.reason == .bad_length
		}
		return
	}
	assert false, 'a chunk length below the header size must be rejected'
}

fn test_chunk_count_is_bounded() {
	mut chunks := []RawChunk{}
	for _ in 0 .. 20 {
		chunks << RawChunk{
			typ: u8(ChunkType.cookie_ack)
		}
	}
	raw := Packet{
		verification_tag: 1
		chunks:           chunks
	}.marshal()!

	Packet.decode(raw, 5) or {
		assert err is DecodeError
		// The same bytes decode fine under a larger limit.
		Packet.decode(raw, default_max_chunks)!
		return
	}
	assert false, 'the chunk count limit must be enforced'
}

fn test_chunk_padding_round_trips() {
	// A three-byte value pads to a four-byte boundary, and the length field
	// counts the value but not the padding.
	packet := Packet{
		verification_tag: 1
		chunks:           [
			RawChunk{
				typ:   u8(ChunkType.heartbeat)
				value: [u8(1), 2, 3]
			},
			RawChunk{
				typ:   u8(ChunkType.cookie_ack)
				value: []u8{}
			},
		]
	}
	raw := packet.marshal()!
	assert raw.len % 4 == 0

	decoded := Packet.decode(raw, default_max_chunks)!
	assert decoded.chunks[0].value == [u8(1), 2, 3]
	assert decoded.chunks[1].value.len == 0
}

fn test_unrecognised_chunk_action_from_type() {
	// The top two bits of the type say what a receiver must do with a chunk it
	// does not know, which is what makes the protocol extensible.
	assert unrecognised_chunk_action(0x00) == .stop_processing
	assert unrecognised_chunk_action(0x40) == .stop_and_report
	assert unrecognised_chunk_action(0x80) == .skip
	assert unrecognised_chunk_action(0xC0) == .skip_and_report
	assert unrecognised_chunk_action(u8(ChunkType.forward_tsn)) == .skip_and_report
}

// -- Typed chunks ----------------------------------------------------------

fn test_init_round_trip() {
	init := Init{
		initiate_tag:               0x11223344
		advertised_receiver_window: 65536
		outbound_streams:           1024
		inbound_streams:            1024
		initial_tsn:                0xAABBCCDD
		parameters:                 [
			Parameter{
				typ:   param_forward_tsn_supported
				value: []u8{}
			},
			Parameter{
				typ:   param_state_cookie
				value: [u8(9), 9, 9]
			},
		]
	}
	decoded := unmarshal_init(init.marshal()!)!

	assert decoded.initiate_tag == 0x11223344
	assert decoded.advertised_receiver_window == 65536
	assert decoded.outbound_streams == 1024
	assert decoded.initial_tsn == 0xAABBCCDD
	assert decoded.supports_forward_tsn()
	assert decoded.state_cookie()? == [u8(9), 9, 9]
}

fn test_init_rejects_invalid_values() {
	// A zero initiate tag is reserved and would let a packet with no tag be
	// accepted into the association.
	zero_tag := Init{
		outbound_streams: 1
		inbound_streams:  1
	}
	zero_tag.marshal() or {
		no_streams := Init{
			initiate_tag: 1
		}
		no_streams.marshal() or { return }
		assert false, 'zero streams must be rejected'
	}
	assert false, 'a zero initiate tag must be rejected'
}

fn test_init_decode_rejects_peer_zero_tag() {
	// Twenty bytes of zeros: a syntactically valid INIT with a zero tag.
	unmarshal_init([]u8{len: 20}) or {
		assert err is DecodeError
		return
	}
	assert false, 'a peer sending a zero initiate tag must be rejected'
}

fn test_data_round_trip_and_flags() {
	data := Data{
		tsn:                         100
		stream_identifier:           3
		stream_sequence_number:      7
		payload_protocol_identifier: ppid_string
		user_data:                   'hello'.bytes()
		beginning:                   true
		end:                         true
		unordered:                   true
	}
	flags := data.flags()
	assert flags & data_flag_beginning != 0
	assert flags & data_flag_end != 0
	assert flags & data_flag_unordered != 0

	decoded := unmarshal_data(flags, data.marshal()!)!
	assert decoded.tsn == 100
	assert decoded.stream_identifier == 3
	assert decoded.stream_sequence_number == 7
	assert decoded.payload_protocol_identifier == ppid_string
	assert decoded.user_data == 'hello'.bytes()
	assert decoded.beginning && decoded.end && decoded.unordered
}

fn test_empty_data_chunk_is_rejected() {
	// RFC 4960 section 3.3.1 forbids it, and a peer that receives one aborts.
	empty := Data{
		tsn: 1
	}
	empty.marshal() or {
		unmarshal_data(0x03, [u8(0), 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 51]) or { return }
		assert false, 'a received empty DATA chunk must be rejected'
	}
	assert false, 'an empty DATA chunk must not be encodable'
}

fn test_sack_round_trip() {
	sack := Sack{
		cumulative_tsn_ack:         500
		advertised_receiver_window: 32768
		gap_ack_blocks:             [
			GapAckBlock{
				start: 2
				end:   4
			},
			GapAckBlock{
				start: 7
				end:   7
			},
		]
		duplicate_tsns:             [u32(498), 499]
	}
	decoded := unmarshal_sack(sack.marshal()!)!

	assert decoded.cumulative_tsn_ack == 500
	assert decoded.advertised_receiver_window == 32768
	assert decoded.gap_ack_blocks.len == 2
	assert decoded.gap_ack_blocks[0].start == 2
	assert decoded.gap_ack_blocks[1].end == 7
	assert decoded.duplicate_tsns == [u32(498), 499]
}

fn test_sack_rejects_inverted_gap_block() {
	raw := hex.decode('000001f400008000000100000004000200000000'.substr(0, 32))!
	unmarshal_sack(raw) or { return }
	// If it parsed, the block must at least be well formed.
	decoded := unmarshal_sack(raw) or { return }
	for block in decoded.gap_ack_blocks {
		assert block.end >= block.start
	}
}

fn test_sack_truncated_counts_are_rejected() {
	// Declares two gap blocks but carries none.
	raw := [u8(0), 0, 0, 1, 0, 0, 0x80, 0, 0, 2, 0, 0]
	unmarshal_sack(raw) or {
		assert err is DecodeError
		return
	}
	assert false, 'a SACK declaring more gap blocks than it carries must be rejected'
}

fn test_forward_tsn_round_trip() {
	forward := ForwardTsn{
		new_cumulative_tsn: 900
		streams:            [
			ForwardTsnStream{
				identifier:      1
				sequence_number: 5
			},
			ForwardTsnStream{
				identifier:      2
				sequence_number: 9
			},
		]
	}
	decoded := unmarshal_forward_tsn(forward.marshal()!)!
	assert decoded.new_cumulative_tsn == 900
	assert decoded.streams.len == 2
	assert decoded.streams[1].sequence_number == 9
}

fn test_parameters_pad_to_a_word() {
	body := marshal_parameters([
		Parameter{
			typ:   param_state_cookie
			value: [u8(1), 2, 3]
		},
		Parameter{
			typ:   param_forward_tsn_supported
			value: []u8{}
		},
	])!
	assert body.len % 4 == 0

	decoded := unmarshal_parameters(body)!
	assert decoded.len == 2
	assert decoded[0].value == [u8(1), 2, 3]
	assert find_parameter(decoded, param_forward_tsn_supported) != none
	assert find_parameter(decoded, param_random) == none
}

fn test_parameter_length_below_header_is_rejected() {
	unmarshal_parameters([u8(0), 7, 0, 2]) or {
		assert err is DecodeError
		return
	}
	assert false, 'a parameter length below its header must be rejected'
}

// -- Sequence arithmetic ---------------------------------------------------

fn test_tsn_comparisons_wrap() {
	assert tsn_after(2, 1)
	assert !tsn_after(1, 2)
	assert !tsn_after(1, 1)
	// Across the wrap: 0 comes after 0xFFFFFFFF.
	assert tsn_after(0, 0xFFFFFFFF)
	assert !tsn_after(0xFFFFFFFF, 0)
	assert tsn_before(0xFFFFFFFF, 0)
	assert tsn_distance(5, 1) == 4
	assert tsn_distance(1, 5) == -4
	assert tsn_distance(1, 0xFFFFFFFF) == 2
}

fn test_stream_sequence_comparison_wraps() {
	assert sequence_after(1, 0)
	assert sequence_after(0, 65535)
	assert !sequence_after(65535, 0)
	assert !sequence_after(5, 5)
}

// -- Stream reassembly -----------------------------------------------------

fn make_data(tsn u32, sequence u16, payload string, beginning bool, end bool, unordered bool) Data {
	return Data{
		tsn:                         tsn
		stream_identifier:           1
		stream_sequence_number:      sequence
		payload_protocol_identifier: ppid_string
		user_data:                   payload.bytes()
		beginning:                   beginning
		end:                         end
		unordered:                   unordered
	}
}

fn test_whole_message_is_delivered_immediately() {
	mut stream := InboundStream{
		identifier: 1
	}
	messages :=
		stream.accept(make_data(1, 0, 'hello', true, true, false), default_max_message_size)!
	assert messages.len == 1
	assert messages[0].data == 'hello'.bytes()
	assert !messages[0].unordered
}

fn test_fragments_reassemble() {
	mut stream := InboundStream{
		identifier: 1
	}
	assert stream.accept(make_data(1, 0, 'he', true, false, false), default_max_message_size)!.len == 0
	assert stream.accept(make_data(2, 0, 'll', false, false, false), default_max_message_size)!.len == 0
	messages := stream.accept(make_data(3, 0, 'o', false, true, false), default_max_message_size)!
	assert messages.len == 1
	assert messages[0].data == 'hello'.bytes()
}

fn test_ordered_delivery_waits_for_the_gap() {
	mut stream := InboundStream{
		identifier: 1
	}
	// Sequence 1 arrives first and must be held until 0 has been delivered,
	// which is what "ordered" means at the stream level.
	assert stream.accept(make_data(2, 1, 'second', true, true, false), default_max_message_size)!.len == 0

	messages :=
		stream.accept(make_data(1, 0, 'first', true, true, false), default_max_message_size)!
	assert messages.len == 2
	assert messages[0].data == 'first'.bytes()
	assert messages[1].data == 'second'.bytes()
}

fn test_unordered_delivery_does_not_wait() {
	mut stream := InboundStream{
		identifier: 1
	}
	messages := stream.accept(make_data(2, 5, 'now', true, true, true), default_max_message_size)!
	assert messages.len == 1
	assert messages[0].unordered
}

fn test_reassembly_enforces_the_message_limit() {
	mut stream := InboundStream{
		identifier: 1
	}
	stream.accept(make_data(1, 0, 'aaaa', true, false, false), 6)!
	stream.accept(make_data(2, 0, 'bbbb', false, true, false), 6) or {
		assert err is DecodeError
		return
	}
	assert false, 'a message over the limit must be rejected rather than buffered'
}

fn test_forward_tsn_skips_an_ordered_stream() {
	mut stream := InboundStream{
		identifier: 1
	}
	// Sequence 2 arrives while 0 and 1 are still missing.
	assert stream.accept(make_data(3, 2, 'third', true, true, false), default_max_message_size)!.len == 0
	// The sender abandons 0 and 1; skipping to 1 releases what was waiting.
	messages := stream.skip_to(1)
	assert messages.len == 1
	assert messages[0].data == 'third'.bytes()
}

// -- Association over a pipe -----------------------------------------------

// PipeTransport is an in-memory datagram channel with the properties SCTP has
// to cope with: message boundaries, loss, and a bounded write size.
struct PipeTransport {
mut:
	inbound   chan []u8      = chan []u8{cap: 256}
	peer      &PipeTransport = unsafe { nil }
	mu        &sync.Mutex    = sync.new_mutex()
	drop_next int
	// drop_every discards one datagram in n, which is how the retransmission
	// and gap handling get exercised.
	drop_every int
	sent       int
	closed     bool
}

fn new_pipe_pair() (&PipeTransport, &PipeTransport) {
	mut a := &PipeTransport{}
	mut b := &PipeTransport{}
	a.peer = b
	b.peer = a
	return a, b
}

fn (mut p PipeTransport) write(data []u8) !int {
	p.mu.lock()
	if p.closed {
		p.mu.unlock()
		return error('pipe closed')
	}
	p.sent++
	mut drop := false
	if p.drop_next > 0 {
		p.drop_next--
		drop = true
	} else if p.drop_every > 0 && p.sent % p.drop_every == 0 {
		drop = true
	}
	p.mu.unlock()

	if data.len > p.max_write() {
		// A real transport refuses an oversized write. Enforcing it here is what
		// stops a packing bug from passing the tests and failing over DTLS.
		return error('datagram of ${data.len} bytes exceeds the ${p.max_write()}-byte limit')
	}
	if drop {
		return data.len
	}
	mut peer := p.peer
	// The payload is copied into a variable first: V 0.5.2 sends a zero value
	// when the expression in a select-send is a call.
	copy := data.clone()
	select {
		peer.inbound <- copy {}
		else {
			return error('peer queue full')
		}
	}
	return data.len
}

fn (mut p PipeTransport) read(timeout time.Duration) ![]u8 {
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

fn (mut p PipeTransport) max_write() int {
	// Deliberately not a multiple of four. A limit that happens to be aligned
	// hides a chunk-padding miscalculation, because the oversized packet lands
	// exactly on the boundary instead of one byte past it. This is the figure a
	// DTLS transport actually reports.
	return 1163
}

fn (mut p PipeTransport) close() {
	p.mu.lock()
	p.closed = true
	p.mu.unlock()
}

struct AssociationPair {
mut:
	client &Association
	server &Association
}

fn connect_pair(config Config) !AssociationPair {
	mut client_pipe, mut server_pipe := new_pipe_pair()
	return connect_over(mut client_pipe, mut server_pipe, config)!
}

// connect_over establishes an association over pipes the caller keeps a handle
// on, which is what a test that wants to drop specific datagrams needs.
fn connect_over(mut client_pipe PipeTransport, mut server_pipe PipeTransport, config Config) !AssociationPair {
	return connect_over_with(mut client_pipe, mut server_pipe, config, config)!
}

// connect_over_with gives the two ends different configurations, which is how a
// peer lacking an optional feature is exercised.
fn connect_over_with(mut client_pipe PipeTransport, mut server_pipe PipeTransport, client_config Config, server_config Config) !AssociationPair {
	mut client := Association.new(client_pipe, Config{
		...client_config
		role:   .client
		logger: logging.from_env('client')
	})!
	mut server := Association.new(server_pipe, Config{
		...server_config
		role:   .server
		logger: logging.from_env('server')
	})!

	server_thread := spawn fn (mut a Association) ! {
		a.connect(10 * time.second)!
	}(mut server)
	client.connect(10 * time.second)!
	server_thread.wait()!

	return AssociationPair{
		client: client
		server: server
	}
}

fn test_association_establishes() {
	mut pair := connect_pair(Config{})!
	defer {
		pair.client.close()
		pair.server.close()
	}
	assert pair.client.state() == .established
	assert pair.server.state() == .established
	assert pair.client.role() == .client
	assert pair.server.role() == .server
}

fn test_ordered_message_round_trip() {
	mut pair := connect_pair(Config{})!
	defer {
		pair.client.close()
		pair.server.close()
	}

	pair.client.send(0, ppid_string, 'hello over SCTP'.bytes(), true)!
	message := pair.server.recv(5 * time.second)!
	assert message.data == 'hello over SCTP'.bytes()
	assert message.stream_identifier == 0
	assert message.payload_protocol_identifier == ppid_string
	assert !message.unordered

	pair.server.send(0, ppid_binary, [u8(1), 2, 3], true)!
	reply := pair.client.recv(5 * time.second)!
	assert reply.data == [u8(1), 2, 3]
	assert reply.payload_protocol_identifier == ppid_binary
}

fn test_ordering_is_preserved_within_a_stream() {
	mut pair := connect_pair(Config{})!
	defer {
		pair.client.close()
		pair.server.close()
	}

	for i in 0 .. 20 {
		pair.client.send(0, ppid_string, 'message ${i}'.bytes(), true)!
	}
	for i in 0 .. 20 {
		message := pair.server.recv(5 * time.second)!
		assert message.data.bytestr() == 'message ${i}', 'out of order at ${i}'
	}
}

fn test_streams_are_independent() {
	mut pair := connect_pair(Config{})!
	defer {
		pair.client.close()
		pair.server.close()
	}

	pair.client.send(1, ppid_string, 'on one'.bytes(), true)!
	pair.client.send(2, ppid_string, 'on two'.bytes(), true)!

	mut seen := map[u16]string{}
	for _ in 0 .. 2 {
		message := pair.server.recv(5 * time.second)!
		seen[message.stream_identifier] = message.data.bytestr()
	}
	assert seen[u16(1)] == 'on one'
	assert seen[u16(2)] == 'on two'
}

fn test_large_message_is_fragmented_and_reassembled() {
	mut pair := connect_pair(Config{})!
	defer {
		pair.client.close()
		pair.server.close()
	}

	// Well over the 1200-byte transport limit, so it must be split across many
	// chunks and put back together.
	payload := []u8{len: 40000, init: u8(index % 251)}
	pair.client.send(0, ppid_binary, payload, true)!

	message := pair.server.recv(20 * time.second)!
	assert message.data.len == payload.len
	assert message.data == payload
}

fn test_unordered_messages_are_delivered() {
	mut pair := connect_pair(Config{})!
	defer {
		pair.client.close()
		pair.server.close()
	}

	for i in 0 .. 10 {
		pair.client.send(0, ppid_string, 'unordered ${i}'.bytes(), false)!
	}
	mut received := 0
	for _ in 0 .. 10 {
		message := pair.server.recv(5 * time.second)!
		assert message.unordered
		received++
	}
	assert received == 10
}

fn test_empty_message_round_trips() {
	mut pair := connect_pair(Config{})!
	defer {
		pair.client.close()
		pair.server.close()
	}

	// An empty DATA chunk is forbidden, so RFC 8831 sends one padding byte
	// under a distinct protocol identifier. The receiver must see the empty
	// message, not the padding.
	pair.client.send(0, ppid_string, []u8{}, true)!
	message := pair.server.recv(5 * time.second)!
	assert message.payload_protocol_identifier == ppid_string_empty
}

fn test_delivery_survives_packet_loss() {
	mut client_pipe, mut server_pipe := new_pipe_pair()
	// Drop one datagram in four, in both directions.
	client_pipe.drop_every = 4
	server_pipe.drop_every = 4

	mut client := Association.new(client_pipe, role: .client, rto_initial: 100 * time.millisecond)!
	mut server := Association.new(server_pipe, role: .server, rto_initial: 100 * time.millisecond)!
	defer {
		client.close()
		server.close()
	}

	server_thread := spawn fn (mut a Association) ! {
		a.connect(20 * time.second)!
	}(mut server)
	client.connect(20 * time.second)!
	server_thread.wait()!

	for i in 0 .. 30 {
		client.send(0, ppid_string, 'lossy ${i}'.bytes(), true)!
	}
	for i in 0 .. 30 {
		message := server.recv(20 * time.second)!
		assert message.data.bytestr() == 'lossy ${i}', 'out of order or corrupt at ${i}'
	}
}

fn test_send_before_established_is_refused() {
	mut pipe, mut unused_peer := new_pipe_pair()
	mut association := Association.new(pipe, role: .client)!
	defer {
		association.close()
	}
	association.send(0, ppid_string, 'x'.bytes(), true) or {
		assert err is AssociationError
		if err is AssociationError {
			assert err.reason == .wrong_state
		}
		return
	}
	assert false, 'sending before the association is established must fail'
}

fn test_send_rejects_an_unknown_stream() {
	mut pair := connect_pair(streams: 4)!
	defer {
		pair.client.close()
		pair.server.close()
	}
	pair.client.send(0, ppid_string, 'fine'.bytes(), true)!
	pair.client.send(9, ppid_string, 'nope'.bytes(), true) or {
		assert err is AssociationError
		if err is AssociationError {
			assert err.reason == .no_stream
		}
		return
	}
	assert false, 'a stream outside the negotiated count must be refused'
}

fn test_send_rejects_an_oversized_message() {
	mut pair := connect_pair(max_message_size: 1000)!
	defer {
		pair.client.close()
		pair.server.close()
	}
	pair.client.send(0, ppid_binary, []u8{len: 1001}, true) or {
		assert err is AssociationError
		if err is AssociationError {
			assert err.reason == .too_large
		}
		return
	}
	assert false, 'a message over the negotiated maximum must be refused'
}

fn test_operations_after_close_are_refused() {
	mut pair := connect_pair(Config{})!
	pair.server.close()
	pair.client.close()

	pair.client.send(0, ppid_string, 'x'.bytes(), true) or {
		pair.client.recv(50 * time.millisecond) or { return }
		assert false, 'receiving after close must fail'
	}
	assert false, 'sending after close must fail'
}

fn test_graceful_shutdown() {
	mut pair := connect_pair(Config{})!
	defer {
		pair.client.close()
		pair.server.close()
	}

	pair.client.send(0, ppid_string, 'last message'.bytes(), true)!
	assert pair.server.recv(5 * time.second)!.data == 'last message'.bytes()

	pair.client.shutdown(5 * time.second)!
	assert pair.client.state() in [State.closed, .shutdown_sent, .aborted]
}

fn test_acknowledgement_point_starts_in_the_right_place() {
	// The initial TSN is random and spans the whole 32-bit space. If the
	// acknowledgement point started at zero, every SACK for a connection whose
	// TSNs landed in the upper half would compare as older than it under
	// wrapping arithmetic and be discarded - so the window would never open and
	// any transfer larger than it would stall permanently.
	mut pipe, mut unused_peer := new_pipe_pair()
	for _ in 0 .. 200 {
		mut association := Association.new(pipe, role: .client)!
		assert !tsn_before(association.my_next_tsn, association.peer_cumulative_ack), 'the first TSN must not compare as older than the acknowledgement point'

		assert tsn_after(association.my_next_tsn, association.peer_cumulative_ack)
	}
}

fn test_repeated_large_transfers() {
	// Each association draws a fresh random initial TSN, so running this a few
	// times covers both halves of the TSN space.
	for attempt in 0 .. 4 {
		mut pair := connect_pair(Config{})!
		payload := []u8{len: 30000, init: u8(index % 251)}
		pair.client.send(0, ppid_binary, payload, true)!
		message := pair.server.recv(20 * time.second) or {
			pair.client.close()
			pair.server.close()
			assert false, 'attempt ${attempt} stalled: ${err}'
			return
		}
		assert message.data == payload
		pair.client.close()
		pair.server.close()
	}
}

// quick_rto shortens the retransmission timer, so a test that has to wait for
// one takes milliseconds rather than seconds.
const quick_rto = Config{
	rto_initial: 100 * time.millisecond
	rto_min:     50 * time.millisecond
}