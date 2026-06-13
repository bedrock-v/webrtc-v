module sdp

// Typed accessors for the attributes WebRTC defines on top of SDP.
//
// They all read from the generic Attribute list rather than from parsed fields,
// so an attribute this implementation does not understand survives a parse and
// re-serialise unchanged. That property matters for renegotiation: dropping an
// attribute the local stack ignores would silently change what the remote peer
// previously agreed to.

// Setup is the DTLS role negotiated by the `a=setup` attribute (RFC 4145,
// applied to DTLS-SRTP by RFC 5763).
pub enum Setup {
	// active: this endpoint will start the DTLS handshake as the client.
	active
	// passive: this endpoint will wait for the peer's ClientHello.
	passive
	// actpass: offered only, meaning "you choose". An answer must never
	// contain it, because it would leave the roles undetermined.
	actpass
	// holdconn: no connection is to be established.
	holdconn
}

pub fn (s Setup) str() string {
	return match s {
		.active { 'active' }
		.passive { 'passive' }
		.actpass { 'actpass' }
		.holdconn { 'holdconn' }
	}
}

pub fn setup_from_string(s string) ?Setup {
	return match s {
		'active' { Setup.active }
		'passive' { Setup.passive }
		'actpass' { Setup.actpass }
		'holdconn' { Setup.holdconn }
		else { none }
	}
}

// answer returns the role an answerer must take in response to an offered role.
pub fn (s Setup) answer() Setup {
	return match s {
		// RFC 5763 section 5: an answerer that receives actpass picks a role,
		// and picking active means it starts the handshake, which avoids a
		// round trip.
		.actpass { Setup.active }
		.active { Setup.passive }
		.passive { Setup.active }
		.holdconn { Setup.holdconn }
	}
}

// Fingerprint is an `a=fingerprint` value: the hash of the peer's certificate,
// which binds the DTLS handshake to the signalled identity.
pub struct Fingerprint {
pub:
	algorithm string
	value     string
}

pub fn (f Fingerprint) str() string {
	return '${f.algorithm} ${f.value}'
}

// RtpMap is an `a=rtpmap` value binding a payload type to a codec.
pub struct RtpMap {
pub:
	payload_type    u8
	encoding_name   string
	clock_rate      u32
	encoding_params string
}

pub fn (r RtpMap) str() string {
	mut s := '${r.payload_type} ${r.encoding_name}/${r.clock_rate}'
	if r.encoding_params != '' {
		s += '/${r.encoding_params}'
	}
	return s
}

// Fmtp is an `a=fmtp` value: format-specific parameters for a payload type.
pub struct Fmtp {
pub:
	payload_type u8
	parameters   string
}

pub fn (f Fmtp) str() string {
	return '${f.payload_type} ${f.parameters}'
}

// RtcpFeedback is an `a=rtcp-fb` value.
pub struct RtcpFeedback {
pub:
	// payload_type is the type the feedback applies to; wildcard is true when
	// the attribute used '*' to mean all of them.
	payload_type u8
	wildcard     bool
	typ          string
	parameter    string
}

pub fn (f RtcpFeedback) str() string {
	pt := if f.wildcard { '*' } else { f.payload_type.str() }
	if f.parameter == '' {
		return '${pt} ${f.typ}'
	}
	return '${pt} ${f.typ} ${f.parameter}'
}

// ExtMap is an `a=extmap` value declaring an RTP header extension (RFC 8285).
pub struct ExtMap {
pub:
	id        u16
	direction Direction
	uri       string
	// attributes carries any extension-specific suffix.
	attributes string
}