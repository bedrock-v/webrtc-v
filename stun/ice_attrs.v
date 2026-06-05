module stun

// The attributes in this file are defined by ICE (RFC 8445 section 7 and
// RFC 5245 before it) but are carried in STUN messages, so they belong with the
// STUN codec rather than with the agent.

// priority returns the PRIORITY attribute: the priority the sender would assign
// to a peer-reflexive candidate learned from this check.
pub fn (m &Message) priority() !u32 {
	attr := m.get(attr_priority) or { return AttributeNotFoundError{
		typ: attr_priority
	} }
	if attr.value.len != 4 {
		return DecodeError{
			reason: .bad_value
			detail: 'PRIORITY is ${attr.value.len} bytes, expected 4'
		}
	}
	return (u32(attr.value[0]) << 24) | (u32(attr.value[1]) << 16) | (u32(attr.value[2]) << 8) | u32(attr.value[3])
}

pub fn (mut m Message) add_priority(priority u32) {
	m.add(attr_priority, [u8(priority >> 24), u8(priority >> 16), u8(priority >> 8), u8(priority)])
}

// has_use_candidate reports whether the USE-CANDIDATE flag is present. The
// controlling agent sets it on the check for the pair it has selected.
pub fn (m &Message) has_use_candidate() bool {
	return m.has(attr_use_candidate)
}

// add_use_candidate appends the USE-CANDIDATE flag, which carries no value.
pub fn (mut m Message) add_use_candidate() {
	m.add(attr_use_candidate, []u8{})
}

// ice_controlling returns the tiebreaker from an ICE-CONTROLLING attribute.
pub fn (m &Message) ice_controlling() !u64 {
	return m.tiebreaker(attr_ice_controlling)
}