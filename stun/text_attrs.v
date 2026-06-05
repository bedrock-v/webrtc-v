module stun

// RFC 8489 caps the textual attributes so a single message cannot be inflated
// with arbitrary text. The limits are in characters for USERNAME, REALM and
// NONCE, and the byte limits below are the UTF-8 worst case the RFC states.
pub const max_username_bytes = 513
pub const max_realm_bytes = 763
pub const max_nonce_bytes = 763
pub const max_software_bytes = 763

// decode_text validates a text attribute's length and rejects payloads that are
// not valid UTF-8. A decoder that let invalid UTF-8 through would hand callers
// a string that misbehaves in comparisons and logging.
fn decode_text(attr RawAttribute, limit int) !string {
	if attr.value.len > limit {
		return DecodeError{
			reason: .bad_value
			detail: '${attr.name()} is ${attr.value.len} bytes, over the ${limit}-byte limit'
		}
	}
	if !is_valid_utf8(attr.value) {
		return DecodeError{
			reason: .bad_value
			detail: '${attr.name()} is not valid UTF-8'
		}
	}
	return attr.value.bytestr()
}

fn encode_text(name string, s string, limit int) ![]u8 {
	b := s.bytes()
	if b.len > limit {
		return EncodeError{
			detail: '${name} is ${b.len} bytes, over the ${limit}-byte limit'
		}
	}
	return b
}

// is_valid_utf8 reports whether b is a well-formed UTF-8 sequence.
//
// The check rejects overlong encodings, surrogate halves and code points above
// U+10FFFF, all of which are ways to smuggle a byte sequence past a naive
// comparison of two strings that should be equal.
fn is_valid_utf8(b []u8) bool {
	mut i := 0
	for i < b.len {
		c := b[i]
		if c < 0x80 {
			i++
			continue
		}
		mut need := 0
		mut code := u32(0)
		mut lower := u32(0)
		if c & 0xE0 == 0xC0 {
			need = 1
			code = u32(c & 0x1F)
			lower = 0x80
		} else if c & 0xF0 == 0xE0 {
			need = 2
			code = u32(c & 0x0F)
			lower = 0x800
		} else if c & 0xF8 == 0xF0 {
			need = 3
			code = u32(c & 0x07)
			lower = 0x10000
		} else {
			return false
		}
		// The final continuation byte is at i + need, so it must be in range.
		if i + need >= b.len {
			return false
		}
		for k in 1 .. need + 1 {
			cont := b[i + k]
			if cont & 0xC0 != 0x80 {
				return false
			}
			code = (code << 6) | u32(cont & 0x3F)
		}
		if code < lower || code > 0x10FFFF {
			return false
		}
		// Surrogate code points are not valid scalar values in UTF-8.
		if code >= 0xD800 && code <= 0xDFFF {
			return false
		}
		i += need + 1
	}
	return true
}

// username returns the USERNAME attribute. For ICE this is the concatenation
// "remote-ufrag:local-ufrag" as seen by the sender.
pub fn (m &Message) username() !string {
	attr := m.get(attr_username) or { return AttributeNotFoundError{
		typ: attr_username
	} }
	return decode_text(attr, max_username_bytes)!
}

// realm returns the REALM attribute used by long-term credentials.
pub fn (m &Message) realm() !string {
	attr := m.get(attr_realm) or { return AttributeNotFoundError{
		typ: attr_realm
	} }
	return decode_text(attr, max_realm_bytes)!
}