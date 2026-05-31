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