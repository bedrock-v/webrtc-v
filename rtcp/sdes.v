module rtcp

import webrtc.internal.codec

// SDES item types from RFC 3550 section 6.5.
pub const sdes_end = u8(0)
pub const sdes_cname = u8(1)
pub const sdes_name = u8(2)
pub const sdes_email = u8(3)
pub const sdes_phone = u8(4)
pub const sdes_location = u8(5)
pub const sdes_tool = u8(6)
pub const sdes_note = u8(7)
pub const sdes_private = u8(8)

// max_sdes_item_bytes is the largest item the 8-bit length field can express.
pub const max_sdes_item_bytes = 255

// SdesItem is one item inside a source description chunk.
pub struct SdesItem {
pub mut:
	typ  u8
	text string
}