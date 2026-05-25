module codec

// Writer is an append-only big-endian byte buffer.
//
// It is the encoding counterpart to Reader. Writing cannot fail, so the methods
// do not return results; the buffer grows as needed. Where a protocol needs a
// length prefix that is only known after the body is written, use mark_u16 /
// mark_u24 together with patch_length.
pub struct Writer {
pub mut:
	buf []u8
}

// Writer.new returns an empty Writer.
pub fn Writer.new() Writer {
	return Writer{
		buf: []u8{}
	}
}

// Writer.with_capacity returns an empty Writer that has already reserved room
// for n bytes, avoiding reallocation for encoders that know their output size.
pub fn Writer.with_capacity(n int) Writer {
	return Writer{
		buf: []u8{len: 0, cap: n}
	}
}

// len reports how many bytes have been written.
@[inline]
pub fn (w &Writer) len() int {
	return w.buf.len
}

pub fn (mut w Writer) u8(v u8) {
	w.buf << v
}

pub fn (mut w Writer) u16(v u16) {
	w.buf << u8(v >> 8)
	w.buf << u8(v)
}

pub fn (mut w Writer) u24(v u32) {
	w.buf << u8(v >> 16)
	w.buf << u8(v >> 8)
	w.buf << u8(v)
}

pub fn (mut w Writer) u32(v u32) {
	w.buf << u8(v >> 24)
	w.buf << u8(v >> 16)
	w.buf << u8(v >> 8)
	w.buf << u8(v)
}

pub fn (mut w Writer) u48(v u64) {
	for shift := 40; shift >= 0; shift -= 8 {
		w.buf << u8(v >> shift)
	}
}