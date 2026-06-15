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

// ParseOptions bounds what a single parse may allocate. A description arrives
// over a signalling channel that the peer controls, so its size is not
// inherently trustworthy.
@[params]
pub struct ParseOptions {
pub:
	max_lines              int = 4096
	max_media_descriptions int = 128
	max_line_length        int = 8192
}