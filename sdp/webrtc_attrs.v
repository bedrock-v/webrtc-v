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

pub fn (e ExtMap) str() string {
	mut s := e.id.str()
	if e.direction != .unspecified {
		s += '/${e.direction}'
	}
	s += ' ${e.uri}'
	if e.attributes != '' {
		s += ' ${e.attributes}'
	}
	return s
}

// SsrcAttribute is an `a=ssrc` value: a per-source attribute such as cname.
pub struct SsrcAttribute {
pub:
	ssrc      u32
	attribute string
	value     string
}

// SsrcGroup is an `a=ssrc-group` value, for example FID pairing a media stream
// with its retransmission stream.
pub struct SsrcGroup {
pub:
	semantics string
	ssrcs     []u32
}

// Msid is an `a=msid` value tying a track to a media stream (RFC 8830).
pub struct Msid {
pub:
	stream_id string
	track_id  string
}

pub fn (m Msid) str() string {
	if m.track_id == '' {
		return m.stream_id
	}
	return '${m.stream_id} ${m.track_id}'
}

// attribute returns the value of the first attribute with the given key.
pub fn attribute(attrs []Attribute, key string) ?string {
	for attr in attrs {
		if attr.key == key {
			return attr.value
		}
	}
	return none
}

// attribute_values returns the values of every attribute with the given key.
pub fn attribute_values(attrs []Attribute, key string) []string {
	mut out := []string{}
	for attr in attrs {
		if attr.key == key {
			out << attr.value
		}
	}
	return out
}

// has_attribute reports whether a flag attribute is present.
pub fn has_attribute(attrs []Attribute, key string) bool {
	for attr in attrs {
		if attr.key == key {
			return true
		}
	}
	return false
}

pub fn (s &SessionDescription) attribute(key string) ?string {
	return attribute(s.attributes, key)
}

pub fn (s &SessionDescription) has_attribute(key string) bool {
	return has_attribute(s.attributes, key)
}

pub fn (m &MediaDescription) attribute(key string) ?string {
	return attribute(m.attributes, key)
}

pub fn (m &MediaDescription) attribute_values(key string) []string {
	return attribute_values(m.attributes, key)
}

pub fn (m &MediaDescription) has_attribute(key string) bool {
	return has_attribute(m.attributes, key)
}

// media_description returns the section with the given `a=mid` value.
pub fn (s &SessionDescription) media_description(mid string) ?MediaDescription {
	for media in s.media_descriptions {
		if got := media.mid() {
			if got == mid {
				return media
			}
		}
	}
	return none
}

// bundle_groups returns the `a=group:BUNDLE` mid lists. Every section named in
// one shares a single ICE and DTLS transport.
pub fn (s &SessionDescription) bundle_groups() [][]string {
	mut out := [][]string{}
	for value in attribute_values(s.attributes, 'group') {
		fields := value.split(' ').filter(it != '')
		if fields.len < 1 || fields[0] != 'BUNDLE' {
			continue
		}
		out << fields[1..].clone()
	}
	return out
}

// mid returns the `a=mid` identifier of a media section.
pub fn (m &MediaDescription) mid() ?string {
	value := attribute(m.attributes, 'mid')?
	if value == '' {
		return none
	}
	return value
}

// direction returns the media direction of a section.
pub fn (m &MediaDescription) direction() Direction {
	for attr in m.attributes {
		if attr.value != '' {
			continue
		}
		if d := direction_from_string(attr.key) {
			return d
		}
	}
	return .unspecified
}

// ice_ufrag returns the `a=ice-ufrag` value, checking the media section first
// and falling back to the session level, as RFC 8839 section 5.4 allows.
pub fn (s &SessionDescription) ice_ufrag(media &MediaDescription) ?string {
	if v := attribute(media.attributes, 'ice-ufrag') {
		return v
	}
	return attribute(s.attributes, 'ice-ufrag')
}

// ice_pwd returns the `a=ice-pwd` value with the same fallback as ice_ufrag.
pub fn (s &SessionDescription) ice_pwd(media &MediaDescription) ?string {
	if v := attribute(media.attributes, 'ice-pwd') {
		return v
	}
	return attribute(s.attributes, 'ice-pwd')
}

// ice_options returns the tokens of the `a=ice-options` attribute, at either
// level. "trickle" here means the peer will send candidates incrementally.
pub fn (s &SessionDescription) ice_options(media &MediaDescription) []string {
	mut raw := attribute(media.attributes, 'ice-options') or {
		attribute(s.attributes, 'ice-options') or { return [] }
	}
	return raw.split(' ').filter(it != '')
}

// fingerprints returns the `a=fingerprint` values of a section, falling back to
// the session level.
//
// More than one may be present when a peer offers several certificates. A
// handshake is acceptable if the peer certificate matches any of them.
pub fn (s &SessionDescription) fingerprints(media &MediaDescription) []Fingerprint {
	mut values := attribute_values(media.attributes, 'fingerprint')
	if values.len == 0 {
		values = attribute_values(s.attributes, 'fingerprint')
	}
	mut out := []Fingerprint{cap: values.len}
	for value in values {
		fields := value.split(' ').filter(it != '')
		if fields.len != 2 {
			continue
		}
		out << Fingerprint{
			algorithm: fields[0].to_lower()
			value:     fields[1].to_lower()
		}
	}
	return out
}

// setup returns the `a=setup` role of a section, falling back to the session
// level.
pub fn (s &SessionDescription) setup(media &MediaDescription) ?Setup {
	raw := attribute(media.attributes, 'setup') or {
		attribute(s.attributes, 'setup') or { return none }
	}
	return setup_from_string(raw)
}

// candidates returns the raw `a=candidate` values. Parsing them belongs to the
// ICE layer, which owns the candidate grammar.
pub fn (m &MediaDescription) candidates() []string {
	return attribute_values(m.attributes, 'candidate')
}

// has_end_of_candidates reports whether the peer has signalled that its
// gathering is complete (RFC 8840).
pub fn (m &MediaDescription) has_end_of_candidates() bool {
	return has_attribute(m.attributes, 'end-of-candidates')
}

// uses_rtcp_mux reports whether RTP and RTCP share one port. WebRTC endpoints
// always do; the attribute is checked rather than assumed because a peer that
// omits it needs a second port.
pub fn (m &MediaDescription) uses_rtcp_mux() bool {
	return has_attribute(m.attributes, 'rtcp-mux')
}

// uses_rtcp_rsize reports whether reduced-size RTCP is permitted (RFC 5506).
pub fn (m &MediaDescription) uses_rtcp_rsize() bool {
	return has_attribute(m.attributes, 'rtcp-rsize')
}

// rtpmaps returns the parsed `a=rtpmap` lines. Malformed entries are skipped
// rather than failing the whole description: an unusable codec line should cost
// that codec, not the session.
pub fn (m &MediaDescription) rtpmaps() []RtpMap {
	mut out := []RtpMap{}
	for value in attribute_values(m.attributes, 'rtpmap') {
		space := value.index(' ') or { continue }
		pt := parse_payload_type(value[..space]) or { continue }
		parts := value[space + 1..].split('/')
		if parts.len < 2 || parts[0] == '' {
			continue
		}
		clock := parse_u32(parts[1]) or { continue }
		out << RtpMap{
			payload_type:    pt
			encoding_name:   parts[0]
			clock_rate:      clock
			encoding_params: if parts.len > 2 { parts[2] } else { '' }
		}
	}
	return out
}

// rtpmap returns the codec bound to a payload type.
pub fn (m &MediaDescription) rtpmap(payload_type u8) ?RtpMap {
	for entry in m.rtpmaps() {
		if entry.payload_type == payload_type {
			return entry
		}
	}
	return none
}

// fmtps returns the parsed `a=fmtp` lines.
pub fn (m &MediaDescription) fmtps() []Fmtp {
	mut out := []Fmtp{}
	for value in attribute_values(m.attributes, 'fmtp') {
		space := value.index(' ') or { continue }
		pt := parse_payload_type(value[..space]) or { continue }
		out << Fmtp{
			payload_type: pt
			parameters:   value[space + 1..]
		}
	}
	return out
}

// fmtp returns the format parameters for a payload type.
pub fn (m &MediaDescription) fmtp(payload_type u8) ?string {
	for entry in m.fmtps() {
		if entry.payload_type == payload_type {
			return entry.parameters
		}
	}
	return none
}

// rtcp_feedback returns the parsed `a=rtcp-fb` lines.
pub fn (m &MediaDescription) rtcp_feedback() []RtcpFeedback {
	mut out := []RtcpFeedback{}
	for value in attribute_values(m.attributes, 'rtcp-fb') {
		fields := value.split(' ').filter(it != '')
		if fields.len < 2 {
			continue
		}
		mut wildcard := false
		mut pt := u8(0)
		if fields[0] == '*' {
			wildcard = true
		} else {
			pt = parse_payload_type(fields[0]) or { continue }
		}
		out << RtcpFeedback{
			payload_type: pt
			wildcard:     wildcard
			typ:          fields[1]
			parameter:    if fields.len > 2 { fields[2..].join(' ') } else { '' }
		}
	}
	return out
}

// extmaps returns the parsed `a=extmap` lines.
pub fn (m &MediaDescription) extmaps() []ExtMap {
	mut out := []ExtMap{}
	for value in attribute_values(m.attributes, 'extmap') {
		fields := value.split(' ').filter(it != '')
		if fields.len < 2 {
			continue
		}
		mut id_field := fields[0]
		mut direction := Direction.unspecified
		if slash := id_field.index('/') {
			direction = direction_from_string(id_field[slash + 1..]) or { Direction.unspecified }
			id_field = id_field[..slash]
		}
		id := parse_u32(id_field) or { continue }
		// RFC 8285 section 4.2: identifiers run from 1 to 14 in the one-byte
		// form and up to 255 in the two-byte form. Zero is never valid.
		if id == 0 || id > 255 {
			continue
		}
		out << ExtMap{
			id:         u16(id)
			direction:  direction
			uri:        fields[1]
			attributes: if fields.len > 2 { fields[2..].join(' ') } else { '' }
		}
	}
	return out
}

// ssrcs returns the parsed `a=ssrc` lines.
pub fn (m &MediaDescription) ssrcs() []SsrcAttribute {
	mut out := []SsrcAttribute{}
	for value in attribute_values(m.attributes, 'ssrc') {
		space := value.index(' ') or { continue }
		ssrc := parse_u32(value[..space]) or { continue }
		rest := value[space + 1..]
		if colon := rest.index(':') {
			out << SsrcAttribute{
				ssrc:      ssrc
				attribute: rest[..colon]
				value:     rest[colon + 1..]
			}
		} else {
			out << SsrcAttribute{
				ssrc:      ssrc
				attribute: rest
			}
		}
	}
	return out
}