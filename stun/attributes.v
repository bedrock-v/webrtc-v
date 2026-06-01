module stun

// Attribute types are kept as plain u16 constants rather than an enum because a
// STUN agent must be able to carry, and reason about, types it does not know.
// Values are from the IANA STUN Attributes registry.

// Comprehension-required range (0x0000-0x7FFF). An unknown attribute in this
// range makes the whole message unprocessable and must be answered with a 420
// error listing it.
pub const attr_mapped_address = u16(0x0001)
pub const attr_username = u16(0x0006)
pub const attr_message_integrity = u16(0x0008)
pub const attr_error_code = u16(0x0009)
pub const attr_unknown_attributes = u16(0x000A)
pub const attr_channel_number = u16(0x000C)
pub const attr_lifetime = u16(0x000D)
pub const attr_xor_peer_address = u16(0x0012)
pub const attr_data = u16(0x0013)
pub const attr_realm = u16(0x0014)
pub const attr_nonce = u16(0x0015)
pub const attr_xor_relayed_address = u16(0x0016)
pub const attr_requested_address_family = u16(0x0017)
pub const attr_even_port = u16(0x0018)
pub const attr_requested_transport = u16(0x0019)
pub const attr_dont_fragment = u16(0x001A)
pub const attr_access_token = u16(0x001B)
pub const attr_message_integrity_sha256 = u16(0x001C)
pub const attr_password_algorithm = u16(0x001D)
pub const attr_userhash = u16(0x001E)
pub const attr_xor_mapped_address = u16(0x0020)
pub const attr_reservation_token = u16(0x0022)
pub const attr_priority = u16(0x0024)
pub const attr_use_candidate = u16(0x0025)
pub const attr_padding = u16(0x0026)
pub const attr_response_port = u16(0x0027)
pub const attr_connection_id = u16(0x002A)

// Comprehension-optional range (0x8000-0xFFFF). Unknown attributes here are
// ignored, which is what makes the protocol extensible.
pub const attr_additional_address_family = u16(0x8000)
pub const attr_address_error_code = u16(0x8001)
pub const attr_password_algorithms = u16(0x8002)
pub const attr_alternate_domain = u16(0x8003)
pub const attr_icmp = u16(0x8004)
pub const attr_software = u16(0x8022)
pub const attr_alternate_server = u16(0x8023)
pub const attr_transaction_transmit_counter = u16(0x8025)
pub const attr_cache_timeout = u16(0x8027)
pub const attr_fingerprint = u16(0x8028)
pub const attr_ice_controlled = u16(0x8029)
pub const attr_ice_controlling = u16(0x802A)
pub const attr_response_origin = u16(0x802B)
pub const attr_other_address = u16(0x802C)
pub const attr_ecn_check = u16(0x802D)
pub const attr_third_party_authorization = u16(0x802E)
pub const attr_mobility_ticket = u16(0x8030)

// Non-standard attributes seen from Chrome. They are comprehension-optional, so
// interoperating only requires being able to name them in logs.
pub const attr_goog_network_info = u16(0xC057)
pub const attr_goog_last_ice_check_received = u16(0xC058)
pub const attr_goog_misc_info = u16(0xC059)

// is_comprehension_required reports whether an agent that does not understand
// this attribute must reject the message (RFC 8489 section 14).
@[inline]
pub fn is_comprehension_required(typ u16) bool {
	return typ <= 0x7FFF
}

// attr_name returns the registered name of an attribute type, or a hex literal
// for types outside the registry. Used only for diagnostics.
pub fn attr_name(typ u16) string {
	return match typ {
		attr_mapped_address { 'MAPPED-ADDRESS' }
		attr_username { 'USERNAME' }
		attr_message_integrity { 'MESSAGE-INTEGRITY' }
		attr_error_code { 'ERROR-CODE' }
		attr_unknown_attributes { 'UNKNOWN-ATTRIBUTES' }
		attr_channel_number { 'CHANNEL-NUMBER' }
		attr_lifetime { 'LIFETIME' }
		attr_xor_peer_address { 'XOR-PEER-ADDRESS' }
		attr_data { 'DATA' }
		attr_realm { 'REALM' }
		attr_nonce { 'NONCE' }
		attr_xor_relayed_address { 'XOR-RELAYED-ADDRESS' }
		attr_requested_address_family { 'REQUESTED-ADDRESS-FAMILY' }
		attr_even_port { 'EVEN-PORT' }
		attr_requested_transport { 'REQUESTED-TRANSPORT' }
		attr_dont_fragment { 'DONT-FRAGMENT' }
		attr_access_token { 'ACCESS-TOKEN' }
		attr_message_integrity_sha256 { 'MESSAGE-INTEGRITY-SHA256' }
		attr_password_algorithm { 'PASSWORD-ALGORITHM' }
		attr_userhash { 'USERHASH' }
		attr_xor_mapped_address { 'XOR-MAPPED-ADDRESS' }
		attr_reservation_token { 'RESERVATION-TOKEN' }
		attr_priority { 'PRIORITY' }
		attr_use_candidate { 'USE-CANDIDATE' }
		attr_padding { 'PADDING' }
		attr_response_port { 'RESPONSE-PORT' }
		attr_connection_id { 'CONNECTION-ID' }
		attr_additional_address_family { 'ADDITIONAL-ADDRESS-FAMILY' }
		attr_address_error_code { 'ADDRESS-ERROR-CODE' }
		attr_password_algorithms { 'PASSWORD-ALGORITHMS' }
		attr_alternate_domain { 'ALTERNATE-DOMAIN' }
		attr_icmp { 'ICMP' }
		attr_software { 'SOFTWARE' }
		attr_alternate_server { 'ALTERNATE-SERVER' }
		attr_transaction_transmit_counter { 'TRANSACTION-TRANSMIT-COUNTER' }
		attr_cache_timeout { 'CACHE-TIMEOUT' }
		attr_fingerprint { 'FINGERPRINT' }
		attr_ice_controlled { 'ICE-CONTROLLED' }
		attr_ice_controlling { 'ICE-CONTROLLING' }
		attr_response_origin { 'RESPONSE-ORIGIN' }
		attr_other_address { 'OTHER-ADDRESS' }
		attr_ecn_check { 'ECN-CHECK' }
		attr_third_party_authorization { 'THIRD-PARTY-AUTHORIZATION' }
		attr_mobility_ticket { 'MOBILITY-TICKET' }
		attr_goog_network_info { 'GOOG-NETWORK-INFO' }
		attr_goog_last_ice_check_received { 'GOOG-LAST-ICE-CHECK-RECEIVED' }
		attr_goog_misc_info { 'GOOG-MISC-INFO' }
		else { '0x' + typ.hex() }
	}
}

// RawAttribute is a type-length-value triple as it appears on the wire.
//
// offset records where the attribute header starts within Message.raw. Decoders
// need it to compute MESSAGE-INTEGRITY and FINGERPRINT, both of which cover the
// bytes preceding themselves; it is zero for attributes that have not been
// encoded yet.
pub struct RawAttribute {
pub:
	typ    u16
	value  []u8
	offset int
}

// name returns the registered name of the attribute type.
pub fn (a RawAttribute) name() string {
	return attr_name(a.typ)
}

pub fn (a RawAttribute) str() string {
	return '${a.name()}: ${a.value.hex()}'
}

// padded_len is the number of bytes the attribute occupies on the wire,
// including the 4-byte header and the padding that aligns the value to a 4-byte
// boundary.
@[inline]
pub fn (a RawAttribute) padded_len() int {
	return 4 + padded_size(a.value.len)
}

// padded_size rounds a value length up to the next 4-byte boundary.
@[inline]
fn padded_size(n int) int {
	rem := n % 4
	if rem == 0 {
		return n
	}
	return n + (4 - rem)
}
