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

pub fn (mut w Writer) u64(v u64) {
	for shift := 56; shift >= 0; shift -= 8 {
		w.buf << u8(v >> shift)
	}
}

pub fn (mut w Writer) bytes(b []u8) {
	w.buf << b
}

pub fn (mut w Writer) string(s string) {
	w.buf << s.bytes()
}

// zeros appends n zero bytes.
pub fn (mut w Writer) zeros(n int) {
	for _ in 0 .. n {
		w.buf << 0
	}
}

// pad appends zero bytes until the buffer length is a multiple of boundary.
// STUN attributes and SCTP chunks are both padded to 4-byte boundaries.
pub fn (mut w Writer) pad(boundary int) {
	if boundary <= 1 {
		return
	}
	rem := w.buf.len % boundary
	if rem != 0 {
		w.zeros(boundary - rem)
	}
}

// mark_u16 reserves two bytes for a length that is not yet known and returns
// the offset to hand back to patch_u16.
pub fn (mut w Writer) mark_u16() int {
	pos := w.buf.len
	w.u16(0)
	return pos
}

// patch_u16 writes the number of bytes appended since mark_u16 into the
// reserved slot.
pub fn (mut w Writer) patch_u16(mark int) {
	length := w.buf.len - mark - 2
	w.buf[mark] = u8(length >> 8)
	w.buf[mark + 1] = u8(length)
}

// mark_u24 reserves three bytes for a length. DTLS handshake bodies use a
// 24-bit length.
pub fn (mut w Writer) mark_u24() int {
	pos := w.buf.len
	w.u24(0)
	return pos
}

// patch_u24 writes the number of bytes appended since mark_u24.
pub fn (mut w Writer) patch_u24(mark int) {
	length := w.buf.len - mark - 3
	w.buf[mark] = u8(length >> 16)
	w.buf[mark + 1] = u8(length >> 8)
	w.buf[mark + 2] = u8(length)
}