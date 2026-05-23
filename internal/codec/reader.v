module codec

// Reader is a bounds-checked, big-endian cursor over a byte slice.
//
// Network byte order is big-endian, so the unprefixed accessors read
// big-endian; the few little-endian fields in the WebRTC stack have
// explicitly named accessors.
//
// A Reader never panics: every accessor validates the remaining length first
// and returns a TruncatedError when the buffer is too short. This is the single
// choke point through which all untrusted bytes in this project pass.
pub struct Reader {
pub:
	data []u8
pub mut:
	pos int
}

// Reader.new returns a Reader positioned at the start of data.
pub fn Reader.new(data []u8) Reader {
	return Reader{
		data: data
	}
}

// remaining reports how many unread bytes are left.
@[inline]
pub fn (r &Reader) remaining() int {
	return r.data.len - r.pos
}

// empty reports whether the cursor has consumed the whole buffer.
@[inline]
pub fn (r &Reader) empty() bool {
	return r.pos >= r.data.len
}

@[inline]
fn (r &Reader) require(n int, field string) ! {
	if n < 0 || r.remaining() < n {
		return TruncatedError{
			field: field
			need:  n
			have:  r.remaining()
		}
	}
}

// u8 reads a single byte.
pub fn (mut r Reader) u8(field string) !u8 {
	r.require(1, field)!
	v := r.data[r.pos]
	r.pos++
	return v
}

// u16 reads a big-endian 16-bit unsigned integer.
pub fn (mut r Reader) u16(field string) !u16 {
	r.require(2, field)!
	v := (u16(r.data[r.pos]) << 8) | u16(r.data[r.pos + 1])
	r.pos += 2
	return v
}

// u24 reads a big-endian 24-bit unsigned integer into a u32.
pub fn (mut r Reader) u24(field string) !u32 {
	r.require(3, field)!
	v := (u32(r.data[r.pos]) << 16) | (u32(r.data[r.pos + 1]) << 8) | u32(r.data[r.pos + 2])
	r.pos += 3
	return v
}

// u32 reads a big-endian 32-bit unsigned integer.
pub fn (mut r Reader) u32(field string) !u32 {
	r.require(4, field)!
	v := (u32(r.data[r.pos]) << 24) | (u32(r.data[r.pos + 1]) << 16) | (u32(r.data[r.pos + 2]) << 8) | u32(r.data[
		r.pos + 3])
	r.pos += 4
	return v
}