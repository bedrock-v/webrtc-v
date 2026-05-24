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