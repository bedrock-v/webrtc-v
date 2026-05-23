module codec

fn test_reader_reads_big_endian_widths() {
	mut r := Reader.new([u8(0x01), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
	assert r.u8('a')! == 0x01
	assert r.u16('b')! == 0x0203
	assert r.u24('c')! == 0x040506
	assert r.remaining() == 2
	assert r.u16('d')! == 0x0708
	assert r.empty()
}

fn test_reader_u32_u48_u64() {
	mut r := Reader.new([u8(0xde), 0xad, 0xbe, 0xef])
	assert r.u32('x')! == 0xdeadbeef

	mut r2 := Reader.new([u8(0x00), 0x01, 0x02, 0x03, 0x04, 0x05])
	assert r2.u48('seq')! == 0x000102030405

	mut r3 := Reader.new([u8(0xff), 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88])
	assert r3.u64('y')! == 0xffeeddccbbaa9988
}

fn test_reader_returns_truncated_error_not_panic() {
	mut r := Reader.new([u8(0x01)])
	if _ := r.u32('missing') {
		assert false, 'expected truncation error'
	} else {
		assert err is TruncatedError
		if err is TruncatedError {
			assert err.field == 'missing'
			assert err.need == 4
			assert err.have == 1
		}
	}
	// A failed read must not move the cursor.
	assert r.pos == 0
}

fn test_reader_empty_buffer_is_safe() {
	mut r := Reader.new([]u8{})
	assert r.remaining() == 0
	assert r.empty()
	r.u8('nothing') or { assert err is TruncatedError }
	assert r.rest().len == 0
}

fn test_reader_bytes_copies_and_view_aliases() {
	mut src := [u8(1), 2, 3, 4]
	mut r := Reader.new(src)
	copied := r.bytes(2, 'copy')!
	assert copied == [u8(1), 2]

	mut r2 := Reader.new(src)
	viewed := r2.view(2, 'view')!
	assert viewed == [u8(1), 2]
	src[0] = 9
	// The copy is unaffected by later mutation of the source buffer.
	assert copied[0] == 1
}

fn test_reader_sub_bounds_nested_decoding() {
	mut r := Reader.new([u8(0x00), 0x02, 0xaa, 0xbb, 0xcc])
	length := r.u16('len')!
	mut nested := r.sub(int(length), 'body')!
	assert nested.u8('n1')! == 0xaa
	assert nested.u8('n2')! == 0xbb
	// The nested reader cannot reach past its declared length.
	nested.u8('overflow') or { assert err is TruncatedError }
	assert r.u8('after')! == 0xcc
}

fn test_reader_skip_and_peek() {
	mut r := Reader.new([u8(1), 2, 3, 4])
	assert r.peek_u8(2)! == 3
	assert r.pos == 0
	r.skip(3, 'skip')!
	assert r.u8('last')! == 4
	r.peek_u8(0) or { assert err is TruncatedError }
}

fn test_reader_rejects_negative_length() {
	mut r := Reader.new([u8(1), 2, 3, 4])
	r.bytes(-1, 'neg') or { assert err is TruncatedError }
	r.skip(-5, 'neg') or { assert err is TruncatedError }
}

fn test_writer_widths_round_trip() {
	mut w := Writer.new()
	w.u8(0x01)
	w.u16(0x0203)
	w.u24(0x040506)
	w.u32(0x0708090a)
	w.u48(0x0b0c0d0e0f10)
	w.u64(0x1112131415161718)

	mut r := Reader.new(w.buf)
	assert r.u8('a')! == 0x01
	assert r.u16('b')! == 0x0203
	assert r.u24('c')! == 0x040506
	assert r.u32('d')! == 0x0708090a
	assert r.u48('e')! == 0x0b0c0d0e0f10
	assert r.u64('f')! == 0x1112131415161718
	assert r.empty()
}

fn test_writer_pad_to_boundary() {
	mut w := Writer.new()
	w.bytes([u8(1), 2, 3, 4, 5])
	w.pad(4)
	assert w.len() == 8
	assert w.buf[5..] == [u8(0), 0, 0]

	mut aligned := Writer.new()
	aligned.bytes([u8(1), 2, 3, 4])
	aligned.pad(4)
	assert aligned.len() == 4
}

fn test_writer_length_marks() {
	mut w := Writer.new()
	mark := w.mark_u16()
	w.bytes([u8(0xaa), 0xbb, 0xcc])
	w.patch_u16(mark)
	assert w.buf == [u8(0x00), 0x03, 0xaa, 0xbb, 0xcc]

	mut w24 := Writer.new()
	m24 := w24.mark_u24()
	w24.zeros(300)
	w24.patch_u24(m24)
	assert w24.buf[0..3] == [u8(0x00), 0x01, 0x2c]
}

fn test_writer_take_resets() {
	mut w := Writer.new()
	w.u16(0x1234)
	out := w.take()
	assert out == [u8(0x12), 0x34]
	assert w.len() == 0
}
