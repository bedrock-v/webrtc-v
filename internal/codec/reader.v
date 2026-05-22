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