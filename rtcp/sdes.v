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

// SdesChunk is the set of items describing one source.
pub struct SdesChunk {
pub mut:
	source u32
	items  []SdesItem
}

// cname returns the canonical name of the source, the identifier that ties
// several synchronisation sources to one participant.
pub fn (c &SdesChunk) cname() ?string {
	for item in c.items {
		if item.typ == sdes_cname {
			return item.text
		}
	}
	return none
}

// SourceDescription is a 202 packet.
pub struct SourceDescription {
pub mut:
	chunks []SdesChunk
}

pub fn (s &SourceDescription) destination_ssrc() []u32 {
	mut out := []u32{cap: s.chunks.len}
	for chunk in s.chunks {
		out << chunk.source
	}
	return out
}

pub fn (s &SourceDescription) marshal() ![]u8 {
	if s.chunks.len > 31 {
		return EncodeError{
			detail: '${s.chunks.len} chunks exceed the 31 the count field can express'
		}
	}
	mut body := codec.Writer.new()
	for chunk in s.chunks {
		body.u32(chunk.source)
		for item in chunk.items {
			if item.typ == sdes_end {
				return EncodeError{
					detail: 'item type 0 terminates a chunk and cannot be written as an item'
				}
			}
			text := item.text.bytes()
			if text.len > max_sdes_item_bytes {
				return EncodeError{
					detail: 'SDES item of ${text.len} bytes exceeds the ${max_sdes_item_bytes}-byte length field'
				}
			}
			body.u8(item.typ)
			body.u8(u8(text.len))
			body.bytes(text)
		}
		// A chunk ends with a zero octet and is then padded to a word boundary
		// with more zeros; there is always at least one.
		body.u8(sdes_end)
		body.pad(4)
	}

	mut w := codec.Writer.with_capacity(header_size + body.len())
	header := Header{
		count:       u8(s.chunks.len)
		packet_type: pt_source_description
	}
	header.marshal_into(mut w, body.len())!
	w.bytes(body.buf)
	return w.buf
}