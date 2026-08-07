module datachannel

import time
import webrtc.sctp

// Sending and receiving on a channel, and the routing loop that feeds it.

// send_text sends a string message.
pub fn (mut c Channel) send_text(text string) ! {
	c.send(text.bytes(), true)!
}

// send_binary sends a binary message.
pub fn (mut c Channel) send_binary(data []u8) ! {
	c.send(data, false)!
}