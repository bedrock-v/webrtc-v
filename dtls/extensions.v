module dtls

import webrtc.internal.codec
import webrtc.srtp

// TLS extensions, as carried in the DTLS ClientHello and ServerHello.
//
// Only the ones a WebRTC handshake needs are decoded into typed structures. The
// rest round-trip as raw bytes, which is what lets an unrecognised extension
// from a peer be echoed or ignored without being lost.

// Extension type numbers from the IANA TLS ExtensionType registry.
pub const ext_supported_groups = u16(10)