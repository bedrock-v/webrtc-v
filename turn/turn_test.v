module turn

import net
import sync
import time
import webrtc.netaddr
import webrtc.stun
import webrtc.transport
import webrtc.ice

// Tests for the relay client.
//
// The client is exercised against a relay implemented here rather than against
// a real server: a test that needs the internet is a test that does not run.
// The stand-in speaks the parts of RFC 8656 the client uses - the long-term
// credential challenge, allocation, permissions, channels, and both framings -
// and it is deliberately strict, refusing anything the RFC says it should.

fn test_channel_data_round_trips() {
	framed := ChannelData{
		channel: 0x4001
		payload: [u8(1), 2, 3, 4, 5]
	}
	encoded := framed.encode()!
	assert encoded.len == channel_header_size + 5
	assert is_channel_data(encoded)

	decoded := decode_channel_data(encoded)!
	assert decoded.channel == 0x4001
	assert decoded.payload == [u8(1), 2, 3, 4, 5]
}

fn test_a_channel_number_outside_the_range_is_refused() {
	for channel in [u16(0), 0x3fff, 0x8000, 0xffff] {
		if _ := ChannelData{
			channel: channel
			payload: [u8(1)]
		}.encode()
		{
			assert false, 'channel ${channel} is not a valid channel number'
		}
	}
}

fn test_channel_data_is_told_apart_from_stun() {
	// RFC 7983 demultiplexes on the first byte, so this is what keeps relayed
	// data from being parsed as a STUN message and the other way round.
	message := stun.Message.new(.request, .allocate)!
	mut copy := message
	encoded := copy.encode()!
	assert !is_channel_data(encoded)

	framed := ChannelData{
		channel: channel_min
		payload: [u8(0)]
	}.encode()!
	assert is_channel_data(framed)
	assert !is_channel_data([]u8{})
	assert !is_channel_data([u8(0x40), 0x00])
}

fn test_truncated_channel_data_is_refused() {
	if _ := decode_channel_data([u8(0x40), 0x01]) {
		assert false, 'a two-byte datagram cannot be channel data'
	}
	// A length field that claims more than the datagram carries.
	if _ := decode_channel_data([u8(0x40), 0x01, 0x00, 0x10, 0x01, 0x02]) {
		assert false, 'the length field must be checked against what arrived'
	}
}

fn test_credentials_are_required() {
	if _ := Client.new('127.0.0.1:3478', ClientConfig{}) {
		assert false, 'a relay without credentials is an open relay'
	}
	if _ := Client.new('127.0.0.1:3478', username: 'u') {
		assert false, 'a password is required too'
	}
}

fn test_a_bad_server_address_is_refused() {
	if _ := Client.new('not-an-address', username: 'u', password: 'p') {
		assert false, 'the server address has to parse'
	}
}

fn test_an_allocation_is_made_and_released() {
	mut server := FakeRelay.start()!
	defer {
		server.stop()
	}

	mut client := Client.new(server.address(), username: 'user', password: 'pass')!
	defer {
		client.close()
	}

	relayed := client.allocate()!
	assert relayed.port != 0
	assert client.relayed_address()? == relayed
	// The allocation response also reports what the relay saw us coming from,
	// which is a server-reflexive candidate for free.
	assert client.mapped_address() != none

	// The first request goes out unauthenticated and is challenged, so the
	// exchange must have taken two transactions.
	assert server.allocate_attempts() == 2
	assert server.last_realm() == 'webrtc-v.test'
}

fn test_the_wrong_password_is_rejected() {
	mut server := FakeRelay.start()!
	defer {
		server.stop()
	}

	mut client := Client.new(server.address(),
		username: 'user'
		password: 'wrong'
		rto:      50 * time.millisecond
	)!
	defer {
		client.close()
	}

	if _ := client.allocate() {
		assert false, 'the relay must not allocate for a bad password'
	} else {
		assert err is TurnError
		if err is TurnError {
			assert err.reason == .unauthorized
			assert err.code == stun.code_wrong_credentials
		}
	}
}

fn test_a_stale_nonce_is_retried() {
	mut server := FakeRelay.start()!
	defer {
		server.stop()
	}

	mut client := Client.new(server.address(), username: 'user', password: 'pass')!
	defer {
		client.close()
	}
	client.allocate()!

	// The relay rotates its nonce, as a real one does periodically. The next
	// request must be answered with 438 and then succeed, without the caller
	// seeing anything.
	server.rotate_nonce()
	peer := netaddr.SocketAddr.parse('203.0.113.7:5000')!
	client.create_permission(peer)!
	assert server.has_permission(peer)
}

fn test_data_is_relayed_through_a_send_indication() {
	mut server := FakeRelay.start()!
	defer {
		server.stop()
	}

	mut client := Client.new(server.address(), username: 'user', password: 'pass')!
	defer {
		client.close()
	}
	client.allocate()!

	peer := netaddr.SocketAddr.parse('203.0.113.7:5000')!
	client.create_permission(peer)!
	client.send_to(peer, 'to the peer'.bytes())!

	sent := server.wait_for_relayed(2 * time.second)!
	assert sent.data == 'to the peer'.bytes()
	assert sent.peer.str() == peer.str()

	// And the other direction: the relay wraps what the peer sent in a Data
	// indication.
	server.deliver_from_peer(peer, 'from the peer'.bytes())!
	received := client.recv(2 * time.second)!
	assert received.data == 'from the peer'.bytes()
	assert received.from.str() == peer.str()
}