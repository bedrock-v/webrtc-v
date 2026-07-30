module sctp

import webrtc.internal.codec

// The typed chunk bodies a WebRTC association exchanges.

// Parameter type numbers from the IANA SCTP registry.
pub const param_heartbeat_info = u16(1)