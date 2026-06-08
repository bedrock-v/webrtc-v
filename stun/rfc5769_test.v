module stun

import encoding.hex
import webrtc.netaddr

// The vectors in RFC 5769 are self-validating: each carries a MESSAGE-INTEGRITY
// computed with a published password and a FINGERPRINT over the whole message.
// Reproducing both from the decoded bytes exercises the header parser, the
// attribute walker, the length-field rewriting that both digests depend on, and
// the XOR-MAPPED-ADDRESS transform in one shot.

// Section 2.1: sample request from an ICE client.
const vector_request = '000100582112a442b7e7a701bc34d686fa87dfae' + '80220010' +