// Package sdp implements the Session Description Protocol (RFC 8866, formerly
// RFC 4566) together with the attributes WebRTC layers on top of it.
//
// SDP is the format WebRTC offers and answers are written in. This package
// treats it as data: it parses and serialises descriptions and gives typed
// access to the attributes that matter, but it does not decide what belongs in
// an offer. That is the job of the peerconnection layer, which sits above it.
module sdp

import strings

// Direction is the media direction declared by a sendrecv, sendonly, recvonly
// or inactive attribute (RFC 8866 section 6.7).
pub enum Direction {
	// unspecified means no direction attribute was present. RFC 8866 says the
	// default is sendrecv, but "absent" and "explicitly sendrecv" are different
	// facts and the distinction matters when re-offering, so it is preserved.
	unspecified
	sendrecv
	sendonly
	recvonly
	inactive
}

// str returns the SDP attribute name for a direction.
//
// The unspecified variant has no attribute name - it means no direction line
// was present - and renders as "unspecified" rather than as an empty string, so
// that interpolating it into a description produces something obviously wrong
// instead of something silently missing. Callers building SDP must check for it
// rather than emitting it.
pub fn (d Direction) str() string {
	return match d {
		.unspecified { 'unspecified' }
		.sendrecv { 'sendrecv' }
		.sendonly { 'sendonly' }
		.recvonly { 'recvonly' }
		.inactive { 'inactive' }
	}
}

// direction_from_string parses a direction attribute name.
pub fn direction_from_string(s string) ?Direction {
	return match s {
		'sendrecv' { Direction.sendrecv }
		'sendonly' { Direction.sendonly }
		'recvonly' { Direction.recvonly }
		'inactive' { Direction.inactive }
		else { none }
	}
}

// reverse returns the direction a peer must adopt to match this one. An offer
// of sendonly is answered with recvonly, and the symmetric directions map to
// themselves.
pub fn (d Direction) reverse() Direction {
	return match d {
		.sendonly { Direction.recvonly }
		.recvonly { Direction.sendonly }
		else { d }
	}
}

// Attribute is one `a=` line: a key, and a value for the `a=key:value` form.
//
// A flag attribute such as `a=rtcp-mux` has an empty value. The distinction
// between `a=key` and `a=key:` is not preserved, because nothing in WebRTC
// depends on it and treating them alike removes a whole class of parsing edge
// case.
pub struct Attribute {
pub:
	key   string
	value string
}

pub fn (a Attribute) str() string {
	if a.value == '' {
		return a.key
	}
	return '${a.key}:${a.value}'
}

// Origin is the `o=` line, which identifies the session.
pub struct Origin {
pub mut:
	username        string = '-'
	session_id      u64
	session_version u64
	network_type    string = 'IN'
	address_type    string = 'IP4'
	unicast_address string = '127.0.0.1'
}

pub fn (o Origin) str() string {
	return '${o.username} ${o.session_id} ${o.session_version} ${o.network_type} ${o.address_type} ${o.unicast_address}'
}

// ConnectionData is the `c=` line.
pub struct ConnectionData {
pub mut:
	network_type string = 'IN'
	address_type string = 'IP4'
	address      string = '0.0.0.0'
	// ttl and range are the optional suffixes on a multicast address. WebRTC
	// never uses them, but they are preserved so a description round-trips.
	ttl   int
	range int
}

pub fn (c ConnectionData) str() string {
	mut addr := c.address
	if c.ttl > 0 {
		addr += '/${c.ttl}'
		if c.range > 0 {
			addr += '/${c.range}'
		}
	}
	return '${c.network_type} ${c.address_type} ${addr}'
}

// Bandwidth is a `b=` line.
pub struct Bandwidth {
pub mut:
	typ   string
	value u64
}

pub fn (b Bandwidth) str() string {
	return '${b.typ}:${b.value}'
}

// TimeDescription is a `t=` line and its `r=` repeats.
pub struct TimeDescription {
pub mut:
	start_time u64
	stop_time  u64
	repeats    []Repeat
}

// Repeat is an `r=` line.
pub struct Repeat {
pub mut:
	interval u64
	active   u64
	offsets  []u64
}

// MediaDescription is one `m=` section: the media line and everything up to the
// next `m=`.
pub struct MediaDescription {
pub mut:
	// media is "audio", "video" or "application".
	media string
	// port is the transport port. In WebRTC it is a placeholder - the real
	// address comes from ICE - except that 0 means the section is rejected.
	port int
	// port_count is the optional `/n` suffix on the port; 0 when absent.
	port_count int
	// protos is the transport protocol split on '/', for example
	// ["UDP", "TLS", "RTP", "SAVPF"].
	protos []string
	// formats are the payload type numbers, or "webrtc-datachannel" for an
	// application section.
	formats        []string
	title          string
	connection     ?ConnectionData
	bandwidth      []Bandwidth
	encryption_key string
	attributes     []Attribute
}

// proto returns the transport protocol as it appears on the wire.
pub fn (m &MediaDescription) proto() string {
	return m.protos.join('/')
}

// is_rejected reports whether the section has been rejected by setting its port
// to zero (RFC 8866 section 5.14 and JSEP section 5.3.1).
@[inline]
pub fn (m &MediaDescription) is_rejected() bool {
	return m.port == 0
}

// SessionDescription is a complete SDP document.
pub struct SessionDescription {
pub mut:
	version             u32
	origin              Origin
	session_name        string = '-'
	session_information string
	uri                 string
	emails              []string
	phones              []string
	connection          ?ConnectionData
	bandwidth           []Bandwidth
	time_descriptions   []TimeDescription
	timezones           string
	encryption_key      string
	attributes          []Attribute
	media_descriptions  []MediaDescription
}

// marshal serialises the description.
//
// Lines are emitted in the order RFC 8866 section 5 requires; a receiver is
// entitled to reject a description whose lines are out of order, and several
// deployed stacks do.
pub fn (s &SessionDescription) marshal() string {
	mut sb := strings.new_builder(1024)

	write_line(mut sb, 'v', s.version.str())
	write_line(mut sb, 'o', s.origin.str())
	write_line(mut sb, 's', if s.session_name == '' { '-' } else { s.session_name })
	if s.session_information != '' {
		write_line(mut sb, 'i', s.session_information)
	}
	if s.uri != '' {
		write_line(mut sb, 'u', s.uri)
	}
	for email in s.emails {
		write_line(mut sb, 'e', email)
	}
	for phone in s.phones {
		write_line(mut sb, 'p', phone)
	}
	if conn := s.connection {
		write_line(mut sb, 'c', conn.str())
	}
	for bw in s.bandwidth {
		write_line(mut sb, 'b', bw.str())
	}
	if s.time_descriptions.len == 0 {
		// A description must carry at least one time line; the WebRTC value is
		// always "0 0", meaning permanent.
		write_line(mut sb, 't', '0 0')
	}
	for td in s.time_descriptions {
		write_line(mut sb, 't', '${td.start_time} ${td.stop_time}')
		for repeat in td.repeats {
			mut parts := [repeat.interval.str(), repeat.active.str()]
			for offset in repeat.offsets {
				parts << offset.str()
			}
			write_line(mut sb, 'r', parts.join(' '))
		}
	}
	if s.timezones != '' {
		write_line(mut sb, 'z', s.timezones)
	}
	if s.encryption_key != '' {
		write_line(mut sb, 'k', s.encryption_key)
	}
	for attr in s.attributes {
		write_line(mut sb, 'a', attr.str())
	}

	for media in s.media_descriptions {
		mut port := media.port.str()
		if media.port_count > 0 {
			port += '/${media.port_count}'
		}
		mut fields := [media.media, port, media.proto()]
		fields << media.formats
		write_line(mut sb, 'm', fields.join(' '))

		if media.title != '' {
			write_line(mut sb, 'i', media.title)
		}
		if conn := media.connection {
			write_line(mut sb, 'c', conn.str())
		}
		for bw in media.bandwidth {
			write_line(mut sb, 'b', bw.str())
		}
		if media.encryption_key != '' {
			write_line(mut sb, 'k', media.encryption_key)
		}
		for attr in media.attributes {
			write_line(mut sb, 'a', attr.str())
		}
	}

	return sb.str()
}

pub fn (s &SessionDescription) str() string {
	return s.marshal()
}

// write_line emits one `<type>=<value>` line. RFC 8866 specifies CRLF, and
// while the parser accepts a bare LF, the serialiser always emits both.
@[inline]
fn write_line(mut sb strings.Builder, typ string, value string) {
	sb.write_string(typ)
	sb.write_string('=')
	sb.write_string(value)
	sb.write_string('\r\n')
}
