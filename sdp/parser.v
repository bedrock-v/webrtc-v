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

// parse decodes an SDP document.
//
// The parser is strict about structure - a description whose lines are out of
// order, or whose required lines are missing, is rejected - and permissive
// about content, keeping unknown attributes verbatim so that a description can
// be re-serialised without losing information the local implementation happens
// not to understand.
pub fn parse(input string, opts ParseOptions) !SessionDescription {
	mut session := SessionDescription{}
	mut lines := split_lines(input)
	if lines.len > opts.max_lines {
		return ParseError{
			line:   opts.max_lines
			detail: 'description has ${lines.len} lines, over the ${opts.max_lines} limit'
		}
	}

	mut index := 0
	mut line_no := 0
	mut seen_version := false
	mut seen_origin := false
	mut seen_name := false

	// Session-level section.
	for index < lines.len {
		line := lines[index]
		line_no = index + 1
		if line.len > opts.max_line_length {
			return ParseError{
				line:   line_no
				detail: 'line is ${line.len} bytes, over the ${opts.max_line_length} limit'
			}
		}
		typ, value := split_line(line) or {
			return ParseError{
				line:   line_no
				detail: err.msg()
			}
		}
		if typ == `m` {
			break
		}
		index++

		match typ {
			`v` {
				if seen_version {
					return ParseError{
						line:   line_no
						detail: 'duplicate v= line'
					}
				}
				seen_version = true
				session.version = parse_u32(value) or {
					return ParseError{
						line:   line_no
						detail: 'bad protocol version: ${err.msg()}'
					}
				}
				if session.version != 0 {
					return ParseError{
						line:   line_no
						detail: 'unsupported SDP version ${session.version}'
					}
				}
			}
			`o` {
				if !seen_version {
					return ParseError{
						line:   line_no
						detail: 'o= line before v='
					}
				}
				seen_origin = true
				session.origin = parse_origin(value) or {
					return ParseError{
						line:   line_no
						detail: err.msg()
					}
				}
			}
			`s` {
				if !seen_origin {
					return ParseError{
						line:   line_no
						detail: 's= line before o='
					}
				}
				seen_name = true
				session.session_name = value
			}
			`i` {
				session.session_information = value
			}
			`u` {
				session.uri = value
			}
			`e` {
				session.emails << value
			}
			`p` {
				session.phones << value
			}
			`c` {
				session.connection = parse_connection(value) or {
					return ParseError{
						line:   line_no
						detail: err.msg()
					}
				}
			}
			`b` {
				session.bandwidth << parse_bandwidth(value) or {
					return ParseError{
						line:   line_no
						detail: err.msg()
					}
				}
			}
			`t` {
				session.time_descriptions << parse_time(value) or {
					return ParseError{
						line:   line_no
						detail: err.msg()
					}
				}
			}
			`r` {
				if session.time_descriptions.len == 0 {
					return ParseError{
						line:   line_no
						detail: 'r= line without a preceding t= line'
					}
				}
				repeat := parse_repeat(value) or {
					return ParseError{
						line:   line_no
						detail: err.msg()
					}
				}
				session.time_descriptions[session.time_descriptions.len - 1].repeats << repeat
			}
			`z` {
				session.timezones = value
			}
			`k` {
				session.encryption_key = value
			}
			`a` {
				session.attributes << parse_attribute(value)
			}
			else {
				return ParseError{
					line:   line_no
					detail: 'unknown line type "${rune(typ)}" at session level'
				}
			}
		}
	}

	if !seen_version || !seen_origin || !seen_name {
		return ParseError{
			line:   line_no
			detail: 'description is missing one of the required v=, o= or s= lines'
		}
	}

	// Media sections.
	for index < lines.len {
		line_no = index + 1
		typ, value := split_line(lines[index]) or {
			return ParseError{
				line:   line_no
				detail: err.msg()
			}
		}
		if typ != `m` {
			return ParseError{
				line:   line_no
				detail: 'expected an m= line, found "${rune(typ)}="'
			}
		}
		index++

		if session.media_descriptions.len >= opts.max_media_descriptions {
			return ParseError{
				line:   line_no
				detail: 'more than ${opts.max_media_descriptions} media sections'
			}
		}
		mut media := parse_media_line(value) or {
			return ParseError{
				line:   line_no
				detail: err.msg()
			}
		}

		for index < lines.len {
			inner_no := index + 1
			inner_typ, inner_value := split_line(lines[index]) or {
				return ParseError{
					line:   inner_no
					detail: err.msg()
				}
			}
			if inner_typ == `m` {
				break
			}
			index++

			match inner_typ {
				`i` {
					media.title = inner_value
				}
				`c` {
					media.connection = parse_connection(inner_value) or {
						return ParseError{
							line:   inner_no
							detail: err.msg()
						}
					}
				}
				`b` {
					media.bandwidth << parse_bandwidth(inner_value) or {
						return ParseError{
							line:   inner_no
							detail: err.msg()
						}
					}
				}
				`k` {
					media.encryption_key = inner_value
				}
				`a` {
					media.attributes << parse_attribute(inner_value)
				}
				else {
					return ParseError{
						line:   inner_no
						detail: 'line type "${rune(inner_typ)}" is not allowed in a media section'
					}
				}
			}
		}
		session.media_descriptions << media
	}

	return session
}

// split_lines breaks the input on CRLF or LF and drops a trailing empty line.
// RFC 8866 mandates CRLF, but bare LF is common enough in the wild - and in
// hand-written test fixtures - that rejecting it would help nobody.
fn split_lines(input string) []string {
	mut out := []string{}
	for raw in input.split('\n') {
		line := raw.trim_right('\r')
		if line == '' {
			continue
		}
		out << line
	}
	return out
}

// split_line splits `<type>=<value>`.
fn split_line(line string) !(u8, string) {
	if line.len < 2 || line[1] != `=` {
		return error('malformed line "${truncate(line, 40)}", expected <type>=<value>')
	}
	typ := line[0]
	if !((typ >= `a` && typ <= `z`) || (typ >= `A` && typ <= `Z`)) {
		return error('line type must be a letter, found byte 0x${typ.hex()}')
	}
	return typ, line[2..]
}

fn truncate(s string, n int) string {
	if s.len <= n {
		return s
	}
	return s[..n] + '...'
}

fn parse_attribute(value string) Attribute {
	if idx := value.index(':') {
		return Attribute{
			key:   value[..idx]
			value: value[idx + 1..]
		}
	}
	return Attribute{
		key: value
	}
}

fn parse_origin(value string) !Origin {
	fields := value.split(' ')
	if fields.len != 6 {
		return error('o= line has ${fields.len} fields, expected 6')
	}
	return Origin{
		username:        fields[0]
		session_id:      parse_u64(fields[1]) or { return error('bad session id: ${err.msg()}') }
		session_version: parse_u64(fields[2]) or {
			return error('bad session version: ${err.msg()}')
		}
		network_type:    fields[3]
		address_type:    fields[4]
		unicast_address: fields[5]
	}
}

fn parse_connection(value string) !ConnectionData {
	fields := value.split(' ')
	if fields.len != 3 {
		return error('c= line has ${fields.len} fields, expected 3')
	}
	parts := fields[2].split('/')
	mut conn := ConnectionData{
		network_type: fields[0]
		address_type: fields[1]
		address:      parts[0]
	}
	if parts.len > 1 {
		conn.ttl = int(parse_u32(parts[1]) or { return error('bad connection TTL: ${err.msg()}') })
	}
	if parts.len > 2 {
		conn.range = int(parse_u32(parts[2]) or {
			return error('bad connection range: ${err.msg()}')
		})
	}
	if parts.len > 3 {
		return error('c= address has ${parts.len} slash-separated parts, expected at most 3')
	}
	return conn
}

fn parse_bandwidth(value string) !Bandwidth {
	idx := value.index(':') or { return error('b= line is missing a colon') }
	typ := value[..idx]
	if typ == '' {
		return error('b= line has an empty bandwidth type')
	}
	return Bandwidth{
		typ:   typ
		value: parse_u64(value[idx + 1..]) or { return error('bad bandwidth value: ${err.msg()}') }
	}
}

fn parse_time(value string) !TimeDescription {
	fields := value.split(' ')
	if fields.len != 2 {
		return error('t= line has ${fields.len} fields, expected 2')
	}
	return TimeDescription{
		start_time: parse_u64(fields[0]) or { return error('bad start time: ${err.msg()}') }
		stop_time:  parse_u64(fields[1]) or { return error('bad stop time: ${err.msg()}') }
	}
}

fn parse_repeat(value string) !Repeat {
	fields := value.split(' ')
	if fields.len < 3 {
		return error('r= line has ${fields.len} fields, expected at least 3')
	}
	mut repeat := Repeat{
		interval: parse_typed_time(fields[0])!
		active:   parse_typed_time(fields[1])!
	}
	for field in fields[2..] {
		repeat.offsets << parse_typed_time(field)!
	}
	return repeat
}

// parse_typed_time reads the compact time form of RFC 8866 section 5.10, where
// a trailing unit letter multiplies the value: 2d is two days.
fn parse_typed_time(field string) !u64 {
	if field == '' {
		return error('empty time value')
	}
	last := field[field.len - 1]
	multiplier := match last {
		`d` { u64(86400) }
		`h` { u64(3600) }
		`m` { u64(60) }
		`s` { u64(1) }
		else { u64(0) }
	}
	if multiplier == 0 {
		return parse_u64(field)!
	}
	base := parse_u64(field[..field.len - 1])!
	if base > u64(-1) / multiplier {
		return error('time value ${field} overflows')
	}
	return base * multiplier
}