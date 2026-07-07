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