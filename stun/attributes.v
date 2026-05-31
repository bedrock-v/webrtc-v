module stun

// Attribute types are kept as plain u16 constants rather than an enum because a
// STUN agent must be able to carry, and reason about, types it does not know.
// Values are from the IANA STUN Attributes registry.

// Comprehension-required range (0x0000-0x7FFF). An unknown attribute in this
// range makes the whole message unprocessable and must be answered with a 420
// error listing it.
pub const attr_mapped_address = u16(0x0001)