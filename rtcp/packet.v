module rtcp

import webrtc.internal.codec

// RawPacket holds a packet this implementation does not decode.
//
// Keeping unknown packets rather than discarding them lets an application
// forward a compound datagram intact - which an SFU must do - and lets a new
// feedback type be handled above this package without changing it.
pub struct RawPacket {
pub mut:
	header Header
	body   []u8
}