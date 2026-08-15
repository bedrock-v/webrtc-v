module webrtc

import time
import webrtc.datachannel

// The public data channel handle.
//
// It wraps datachannel.Channel so that a channel can be handed back before the
// transports exist: an application creates one, then negotiates, and the handle
// becomes usable when SCTP comes up. Without the wrapper the application would
// have to re-fetch the channel after connecting, which the browser API does not
// make it do.

// DataChannelState mirrors RTCDataChannel.readyState.
pub enum DataChannelState {
	connecting
	open
	closing
	closed
}