module sdp

// ParseError describes where and why a description could not be parsed. The
// line number lets an operator find the offending line in a description that is
// often hundreds of lines long.
pub struct ParseError {
pub:
	line   int
	detail string
}

pub fn (e ParseError) msg() string {
	return 'sdp: line ${e.line}: ${e.detail}'
}

pub fn (e ParseError) code() int {
	return 1
}