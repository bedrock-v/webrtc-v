module stun

import webrtc.internal.codec

// The TURN attributes (RFC 8656).
//
// They are STUN attributes, so they live in the STUN codec next to the rest;
// what uses them is the `turn` module. Keeping the encoding here means the
// relay client is protocol logic with no parsing in it, which is the same split
// the ICE agent and the STUN codec already have.

// max_turn_data is the largest DATA attribute this decoder will accept.
//
// It is the same as the default message limit, so in practice a peer that tries
// to exceed it is stopped by the message bound first. It is stated separately
// because a caller that raises the message limit should not silently raise how
// much a relay can hand back in one datagram.
pub const max_turn_data = 8192