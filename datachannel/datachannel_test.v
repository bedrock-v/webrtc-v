module datachannel

import sync
import time
import webrtc.sctp

// -- DCEP ------------------------------------------------------------------

fn test_open_round_trip() {
	open := Open{
		channel_type:          .partial_reliable_rexmit_unordered
		priority:              256
		reliability_parameter: 3
		label:                 'chat'
		protocol:              'json'
	}
	decoded := Open.decode(open.marshal()!)!

	assert decoded.channel_type == .partial_reliable_rexmit_unordered
	assert decoded.priority == 256
	assert decoded.reliability_parameter == 3
	assert decoded.label == 'chat'
	assert decoded.protocol == 'json'
}

fn test_open_with_empty_label_and_protocol() {
	open := Open{}
	decoded := Open.decode(open.marshal()!)!
	assert decoded.label == ''
	assert decoded.protocol == ''
	assert decoded.channel_type == .reliable
}

fn test_channel_type_properties() {
	// The unordered variants are the ordered ones with the high bit set, which
	// is why they are 0x80 apart rather than sequential.
	assert ChannelType.reliable.is_ordered()
	assert ChannelType.reliable.is_reliable()
	assert !ChannelType.reliable_unordered.is_ordered()
	assert ChannelType.reliable_unordered.is_reliable()
	assert ChannelType.partial_reliable_rexmit.is_ordered()
	assert !ChannelType.partial_reliable_rexmit.is_reliable()
	assert !ChannelType.partial_reliable_timed_unordered.is_ordered()
	assert !ChannelType.partial_reliable_timed_unordered.is_reliable()
}

fn test_open_rejects_malformed_input() {
	cases := [
		[]u8{}, // empty
		[u8(0x02)], // an ACK, not an OPEN
		[u8(0x03), 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // unknown channel type
		[u8(0x03), 0x00, 0, 0, 0, 0, 0, 0], // truncated header
		[u8(0x03), 0x00, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0], // label longer than the body
	]
	for encoded in cases {
		Open.decode(encoded) or { continue }
		assert false, 'expected ${encoded.hex()} to be rejected'
	}
}

fn test_open_enforces_label_limit() {
	long := Open{
		label: 'x'.repeat(max_label_bytes + 1)
	}
	long.marshal() or { return }
	assert false, 'an over-long label must be rejected'
}

fn test_ack_message() {
	assert is_ack(ack_message())
	assert !is_ack([]u8{})
	assert !is_ack([u8(0x03)])
	assert !is_ack([u8(0x02), 0x00])
}

fn test_channel_options_map_to_types() {
	assert ChannelOptions{}.channel_type()! == .reliable
	assert ChannelOptions{
		ordered: false
	}.channel_type()! == .reliable_unordered
	assert ChannelOptions{
		max_retransmits: u16(3)
	}.channel_type()! == .partial_reliable_rexmit
	assert ChannelOptions{
		max_retransmits: u16(3)
		ordered:         false
	}.channel_type()! == .partial_reliable_rexmit_unordered
	assert ChannelOptions{
		max_packet_lifetime: u16(500)
	}.channel_type()! == .partial_reliable_timed
	assert ChannelOptions{
		max_retransmits: u16(3)
	}.reliability_parameter() == 3
	assert ChannelOptions{
		max_packet_lifetime: u16(500)
	}.reliability_parameter() == 500
	assert ChannelOptions{}.reliability_parameter() == 0
}

fn test_channel_options_reject_both_limits() {
	// RFC 8832 section 6.1: a channel is reliable, retransmit-limited or
	// time-limited, never two of them.
	options := ChannelOptions{
		max_retransmits:     u16(3)
		max_packet_lifetime: u16(500)
	}
	options.channel_type() or { return }
	assert false, 'setting both reliability limits must be rejected'
}

// -- Over a real association -----------------------------------------------

struct PipeTransport {
mut:
	inbound chan []u8      = chan []u8{cap: 512}
	peer    &PipeTransport = unsafe { nil }
	mu      &sync.Mutex    = sync.new_mutex()
	closed  bool
	// drop_next discards this many outgoing datagrams, which is how a lost
	// message is arranged for.
	drop_next int
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
	closed := p.closed
	p.mu.unlock()
	if closed {
		return error('pipe closed')
	}
	if data.len > p.max_write() {
		return error('datagram of ${data.len} bytes exceeds the limit')
	}
	p.mu.lock()
	mut drop := false
	if p.drop_next > 0 {
		p.drop_next--
		drop = true
	}
	p.mu.unlock()
	if drop {
		return data.len
	}

	mut peer := p.peer
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
	// Not a multiple of four, matching what a DTLS transport reports, so a
	// chunk-padding miscalculation shows up here rather than end to end.
	return 1163
}

struct Endpoints {
mut:
	client_association &sctp.Association
	server_association &sctp.Association
	client             &Manager
	server             &Manager
}

fn connect_endpoints() !Endpoints {
	mut client_pipe, mut server_pipe := new_pipe_pair()
	return connect_endpoints_over(mut client_pipe, mut server_pipe)!
}

fn connect_endpoints_over(mut client_pipe PipeTransport, mut server_pipe PipeTransport) !Endpoints {
	mut client_association := sctp.Association.new(client_pipe,
		role:        .client
		rto_initial: 100 * time.millisecond
		rto_min:     50 * time.millisecond
	)!
	mut server_association := sctp.Association.new(server_pipe,
		role:        .server
		rto_initial: 100 * time.millisecond
		rto_min:     50 * time.millisecond
	)!

	server_thread := spawn fn (mut a sctp.Association) ! {
		a.connect(10 * time.second)!
	}(mut server_association)
	client_association.connect(10 * time.second)!
	server_thread.wait()!

	// The identifier parity follows the DTLS role: the client takes the even
	// stream identifiers and the server the odd ones.
	client := Manager.new(client_association, is_dtls_client: true)
	server := Manager.new(server_association, is_dtls_client: false)

	return Endpoints{
		client_association: client_association
		server_association: server_association
		client:             client
		server:             server
	}
}

fn (mut e Endpoints) shutdown() {
	e.client.close()
	e.server.close()
	e.client_association.close()
	e.server_association.close()
}

fn test_channel_opens_and_is_accepted() {
	mut endpoints := connect_endpoints()!
	defer {
		endpoints.shutdown()
	}

	mut opened := endpoints.client.create('chat', ChannelOptions{}, 5 * time.second)!
	assert opened.state() == .open
	assert opened.label == 'chat'
	// The DTLS client uses even stream identifiers.
	assert opened.stream_identifier % 2 == 0

	mut accepted := endpoints.server.accept(5 * time.second)!
	assert accepted.label == 'chat'
	assert accepted.stream_identifier == opened.stream_identifier
	assert accepted.state() == .open
	assert accepted.ordered()
	assert accepted.reliable()
}

fn test_messages_flow_both_ways() {
	mut endpoints := connect_endpoints()!
	defer {
		endpoints.shutdown()
	}

	mut sender := endpoints.client.create('chat', ChannelOptions{}, 5 * time.second)!
	mut receiver := endpoints.server.accept(5 * time.second)!

	sender.send_text('hello over a data channel')!
	message := receiver.recv(5 * time.second)!
	assert message.is_string
	assert message.text() == 'hello over a data channel'

	receiver.send_binary([u8(1), 2, 3, 4])!
	reply := sender.recv(5 * time.second)!
	assert !reply.is_string
	assert reply.data == [u8(1), 2, 3, 4]
}

fn test_string_and_binary_stay_distinguishable_when_empty() {
	mut endpoints := connect_endpoints()!
	defer {
		endpoints.shutdown()
	}

	mut sender := endpoints.client.create('empties', ChannelOptions{}, 5 * time.second)!
	mut receiver := endpoints.server.accept(5 * time.second)!

	// An empty message cannot be an empty SCTP chunk, so it travels as one
	// padding byte under a protocol identifier of its own. The receiver must
	// see an empty message of the right kind, not the padding.
	sender.send_text('')!
	first := receiver.recv(5 * time.second)!
	assert first.is_string
	assert first.data.len == 0

	sender.send_binary([]u8{})!
	second := receiver.recv(5 * time.second)!
	assert !second.is_string
	assert second.data.len == 0
}

fn test_several_channels_are_independent() {
	mut endpoints := connect_endpoints()!
	defer {
		endpoints.shutdown()
	}

	mut first := endpoints.client.create('first', ChannelOptions{}, 5 * time.second)!
	mut accepted_first := endpoints.server.accept(5 * time.second)!
	mut second := endpoints.client.create('second', ChannelOptions{}, 5 * time.second)!
	mut accepted_second := endpoints.server.accept(5 * time.second)!

	assert first.stream_identifier != second.stream_identifier
	assert accepted_first.label == 'first'
	assert accepted_second.label == 'second'

	first.send_text('on the first')!
	second.send_text('on the second')!

	assert accepted_first.recv(5 * time.second)!.text() == 'on the first'
	assert accepted_second.recv(5 * time.second)!.text() == 'on the second'
}

fn test_unordered_channel_reports_its_properties() {
	mut endpoints := connect_endpoints()!
	defer {
		endpoints.shutdown()
	}

	mut sender := endpoints.client.create('fast', ChannelOptions{
		ordered:         false
		max_retransmits: u16(0)
	}, 5 * time.second)!
	mut receiver := endpoints.server.accept(5 * time.second)!

	assert !sender.ordered()
	assert !sender.reliable()
	// The peer learns the channel's properties from the OPEN message.
	assert !receiver.ordered()
	assert !receiver.reliable()

	sender.send_text('unordered')!
	assert receiver.recv(5 * time.second)!.text() == 'unordered'
}

fn test_large_message_crosses_a_channel() {
	mut endpoints := connect_endpoints()!
	defer {
		endpoints.shutdown()
	}

	mut sender := endpoints.client.create('bulk', ChannelOptions{}, 5 * time.second)!
	mut receiver := endpoints.server.accept(5 * time.second)!

	payload := []u8{len: 50000, init: u8(index % 251)}
	sender.send_binary(payload)!
	message := receiver.recv(20 * time.second)!
	assert message.data.len == payload.len
	assert message.data == payload
}

fn test_ordering_is_preserved_on_a_channel() {
	mut endpoints := connect_endpoints()!
	defer {
		endpoints.shutdown()
	}

	mut sender := endpoints.client.create('ordered', ChannelOptions{}, 5 * time.second)!
	mut receiver := endpoints.server.accept(5 * time.second)!

	for i in 0 .. 25 {
		sender.send_text('message ${i}')!
	}
	for i in 0 .. 25 {
		assert receiver.recv(5 * time.second)!.text() == 'message ${i}', 'out of order at ${i}'
	}
}

fn test_negotiated_channel_needs_no_handshake() {
	mut endpoints := connect_endpoints()!
	defer {
		endpoints.shutdown()
	}

	// Both applications already agreed on stream 100, so neither waits a round
	// trip for DCEP.
	mut client_side := endpoints.client.create_negotiated(100, 'agreed', ChannelOptions{})!
	mut server_side := endpoints.server.create_negotiated(100, 'agreed', ChannelOptions{})!

	assert client_side.state() == .open
	assert server_side.state() == .open
	assert client_side.negotiated

	client_side.send_text('no handshake needed')!
	assert server_side.recv(5 * time.second)!.text() == 'no handshake needed'
}

fn test_negotiated_channel_rejects_a_used_stream() {
	mut endpoints := connect_endpoints()!
	defer {
		endpoints.shutdown()
	}

	endpoints.client.create_negotiated(100, 'first', ChannelOptions{})!
	endpoints.client.create_negotiated(100, 'second', ChannelOptions{}) or {
		assert err is ChannelError
		return
	}
	assert false, 'reusing a stream identifier must be refused'
}

fn test_stream_identifiers_do_not_collide_between_ends() {
	mut endpoints := connect_endpoints()!
	defer {
		endpoints.shutdown()
	}

	mut from_client := endpoints.client.create('from client', ChannelOptions{}, 5 * time.second)!
	endpoints.server.accept(5 * time.second)!
	mut from_server := endpoints.server.create('from server', ChannelOptions{}, 5 * time.second)!
	endpoints.client.accept(5 * time.second)!

	// The parity split is what keeps both ends from choosing the same stream.
	assert from_client.stream_identifier % 2 == 0
	assert from_server.stream_identifier % 2 == 1
}

fn test_send_on_a_closed_channel_is_refused() {
	mut endpoints := connect_endpoints()!
	defer {
		endpoints.shutdown()
	}

	mut channel := endpoints.client.create('closing', ChannelOptions{}, 5 * time.second)!
	endpoints.server.accept(5 * time.second)!

	channel.close()
	assert channel.state() == .closed
	channel.send_text('too late') or {
		assert err is ChannelError
		if err is ChannelError {
			assert err.reason == .wrong_state
		}
		return
	}
	assert false, 'sending on a closed channel must be refused'
}

fn test_channels_close_when_the_association_ends() {
	mut endpoints := connect_endpoints()!
	mut channel := endpoints.client.create('doomed', ChannelOptions{}, 5 * time.second)!
	endpoints.server.accept(5 * time.second)!
	assert channel.state() == .open

	endpoints.client_association.close()

	deadline := time.now().add(5 * time.second)
	for time.now() < deadline {
		if channel.state() == .closed {
			break
		}
		time.sleep(10 * time.millisecond)
	}
	assert channel.state() == .closed, 'a channel must close when its association ends'

	endpoints.client.close()
	endpoints.server.close()
	endpoints.server_association.close()
}

fn test_accept_times_out_without_a_channel() {
	mut endpoints := connect_endpoints()!
	defer {
		endpoints.shutdown()
	}
	endpoints.server.accept(50 * time.millisecond) or {
		assert err is ChannelError
		if err is ChannelError {
			assert err.reason == .timed_out
		}
		return
	}
	assert false, 'accept must time out when no channel is opened'
}

fn test_an_unreliable_channel_drops_a_lost_message() {
	// max_retransmits: 0 has to reach the association, or the channel is only
	// unreliable in the SDP: the message would be retransmitted and arrive late
	// instead of being abandoned.
	mut client_pipe, mut server_pipe := new_pipe_pair()
	mut endpoints := connect_endpoints_over(mut client_pipe, mut server_pipe)!
	defer {
		endpoints.shutdown()
	}

	mut sender := endpoints.client.create('unreliable', ChannelOptions{ max_retransmits: 0 },
		5 * time.second)!
	mut receiver := endpoints.server.accept(5 * time.second)!
	assert !receiver.reliable()

	client_pipe.drop_next = 1
	sender.send_text('dropped')!
	// A second channel carries the sentinel, so it is not subject to the same
	// policy and must arrive however the first message ends up.
	mut reliable := endpoints.client.create('reliable', ChannelOptions{}, 5 * time.second)!
	mut reliable_receiver := endpoints.server.accept(5 * time.second)!
	reliable.send_text('sentinel')!

	message := reliable_receiver.recv(5 * time.second)!
	assert message.text() == 'sentinel'
	assert receiver.try_recv() == none, 'the abandoned message should not have arrived'
}