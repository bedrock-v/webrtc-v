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