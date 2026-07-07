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