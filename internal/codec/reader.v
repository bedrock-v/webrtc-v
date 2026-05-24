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

// u48 reads a big-endian 48-bit unsigned integer into a u64. DTLS sequence
// numbers use this width.
pub fn (mut r Reader) u48(field string) !u64 {
	r.require(6, field)!
	mut v := u64(0)
	for i in 0 .. 6 {
		v = (v << 8) | u64(r.data[r.pos + i])
	}
	r.pos += 6
	return v
}

// u64 reads a big-endian 64-bit unsigned integer.
pub fn (mut r Reader) u64(field string) !u64 {
	r.require(8, field)!
	mut v := u64(0)
	for i in 0 .. 8 {
		v = (v << 8) | u64(r.data[r.pos + i])
	}
	r.pos += 8
	return v
}

// bytes reads n bytes and returns a copy. Use this whenever the result outlives
// the buffer being decoded, which is the common case for parsed structures.
pub fn (mut r Reader) bytes(n int, field string) ![]u8 {
	r.require(n, field)!
	out := r.data[r.pos..r.pos + n].clone()
	r.pos += n
	return out
}

// view reads n bytes and returns a slice that aliases the underlying buffer.
// Cheaper than bytes, but the caller must not retain it past the lifetime of
// the source buffer, and must not mutate it.
pub fn (mut r Reader) view(n int, field string) ![]u8 {
	r.require(n, field)!
	out := unsafe { r.data[r.pos..r.pos + n] }
	r.pos += n
	return out
}

// rest returns a copy of everything left in the buffer and moves to the end.
pub fn (mut r Reader) rest() []u8 {
	out := r.data[r.pos..].clone()
	r.pos = r.data.len
	return out
}

// rest_view returns the remainder as an aliasing slice and moves to the end.
pub fn (mut r Reader) rest_view() []u8 {
	out := unsafe { r.data[r.pos..] }
	r.pos = r.data.len
	return out
}