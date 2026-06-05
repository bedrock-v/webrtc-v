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