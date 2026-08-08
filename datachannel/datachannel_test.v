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