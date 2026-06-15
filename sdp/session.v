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