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