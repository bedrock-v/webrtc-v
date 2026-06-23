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

fn decode_source_description(header Header, body []u8) !SourceDescription {
	mut r := codec.Reader.new(body)
	mut out := SourceDescription{
		chunks: []SdesChunk{cap: int(header.count)}
	}

	for i in 0 .. int(header.count) {
		source := r.u32('chunk ${i} source') or {
			return DecodeError{
				reason: .bad_length
				detail: 'SourceDescription declares ${header.count} chunks but chunk ${i} is truncated'
			}
		}
		mut chunk := SdesChunk{
			source: source
		}
		for {
			typ := r.u8('item type') or {
				return DecodeError{
					reason: .bad_length
					detail: 'SDES chunk ${i} is not terminated'
				}
			}
			if typ == sdes_end {
				break
			}
			length := int(r.u8('item length') or {
				return DecodeError{
					reason: .bad_length
					detail: 'SDES item in chunk ${i} has no length byte'
				}
			})
			text := r.bytes(length, 'item text') or {
				return DecodeError{
					reason: .bad_length
					detail: 'SDES item in chunk ${i} declares ${length} bytes but only ${r.remaining()} remain'
				}
			}
			chunk.items << SdesItem{
				typ:  typ
				text: text.bytestr()
			}
		}
		// Skip the zero padding that aligns the next chunk to a word boundary.
		for r.remaining() > 0 && r.pos % 4 != 0 {
			pad := r.u8('chunk padding')!
			if pad != sdes_end {
				return DecodeError{
					reason: .bad_padding
					detail: 'SDES chunk ${i} padding contains a non-zero byte'
				}
			}
		}
		out.chunks << chunk
	}
	return out
}

// Goodbye is a 203 packet: the listed sources are leaving the session.
pub struct Goodbye {
pub mut:
	sources []u32
	reason  string
}

pub fn (g &Goodbye) destination_ssrc() []u32 {
	return g.sources.clone()
}

pub fn (g &Goodbye) marshal() ![]u8 {
	if g.sources.len > 31 {
		return EncodeError{
			detail: '${g.sources.len} sources exceed the 31 the count field can express'
		}
	}
	reason := g.reason.bytes()
	if reason.len > 255 {
		return EncodeError{
			detail: 'goodbye reason of ${reason.len} bytes exceeds the 255-byte length field'
		}
	}

	mut body := codec.Writer.new()
	for source in g.sources {
		body.u32(source)
	}
	if reason.len > 0 {
		body.u8(u8(reason.len))
		body.bytes(reason)
		body.pad(4)
	}

	mut w := codec.Writer.with_capacity(header_size + body.len())
	header := Header{
		count:       u8(g.sources.len)
		packet_type: pt_goodbye
	}
	header.marshal_into(mut w, body.len())!
	w.bytes(body.buf)
	return w.buf
}

fn decode_goodbye(header Header, body []u8) !Goodbye {
	mut r := codec.Reader.new(body)
	mut out := Goodbye{
		sources: []u32{cap: int(header.count)}
	}
	for i in 0 .. int(header.count) {
		out.sources << r.u32('goodbye source ${i}') or {
			return DecodeError{
				reason: .bad_length
				detail: 'Goodbye declares ${header.count} sources but source ${i} is truncated'
			}
		}
	}
	if r.remaining() > 0 {
		length := int(r.u8('reason length')!)
		text := r.bytes(length, 'reason') or {
			return DecodeError{
				reason: .bad_length
				detail: 'Goodbye reason declares ${length} bytes but only ${r.remaining()} remain'
			}
		}
		out.reason = text.bytestr()
	}
	return out
}

// ApplicationDefined is a 204 packet, reserved for experimental use.
pub struct ApplicationDefined {
pub mut:
	// subtype is the five-bit field the application may use freely.
	subtype u8
	ssrc    u32
	// name is a four-character ASCII identifier chosen by the application.
	name string
	data []u8
}

pub fn (a &ApplicationDefined) destination_ssrc() []u32 {
	return [a.ssrc]
}