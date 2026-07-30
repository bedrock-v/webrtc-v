module sctp

import webrtc.internal.codec

// The typed chunk bodies a WebRTC association exchanges.

// Parameter type numbers from the IANA SCTP registry.
pub const param_heartbeat_info = u16(1)
pub const param_ipv4_address = u16(5)
pub const param_ipv6_address = u16(6)
pub const param_state_cookie = u16(7)
pub const param_unrecognized = u16(8)
pub const param_cookie_preservative = u16(9)
pub const param_host_name = u16(11)
pub const param_supported_address_types = u16(12)
pub const param_outgoing_ssn_reset = u16(13)
pub const param_incoming_ssn_reset = u16(14)
pub const param_reconfig_response = u16(16)
pub const param_random = u16(0x8002)
pub const param_chunk_list = u16(0x8003)
pub const param_hmac_algorithm = u16(0x8004)
pub const param_padding = u16(0x8005)
pub const param_supported_extensions = u16(0x8008)
pub const param_forward_tsn_supported = u16(0xC000)