module codec

// TruncatedError is returned when a read would run past the end of the buffer.
// Every decoder in this project surfaces malformed input as an error instead of
// panicking, so a hostile peer cannot crash the process with a short packet.
pub struct TruncatedError {
pub:
	// field names the value that could not be read, for diagnostics.
	field string
	// need is the number of bytes the read required.
	need int
	// have is the number of bytes that were actually available.
	have int
}

pub fn (e TruncatedError) msg() string {
	if e.field.len > 0 {
		return 'truncated input reading ${e.field}: need ${e.need} bytes, have ${e.have}'
	}
	return 'truncated input: need ${e.need} bytes, have ${e.have}'
}

pub fn (e TruncatedError) code() int {
	return 1
}

// LimitExceededError is returned when a length prefix declares more data than
// the caller is willing to allocate. Decoders use it to bound memory taken from
// untrusted length fields.
pub struct LimitExceededError {
pub:
	field string
	value int
	limit int
}

pub fn (e LimitExceededError) msg() string {
	return 'value for ${e.field} exceeds limit: ${e.value} > ${e.limit}'
}

pub fn (e LimitExceededError) code() int {
	return 2
}
