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