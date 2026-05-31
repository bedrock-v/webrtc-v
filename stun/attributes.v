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