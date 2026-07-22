module dtls

import crypto.ecdsa
import crypto.sha256
import time
import webrtc.internal.codec
import webrtc.logging
import webrtc.srtp

// The DTLS 1.2 handshake state machine.
//
// The handshake is driven synchronously: handshake() sends a flight, waits for
// the reply, retransmits on a doubling timer, and returns when both sides have
// verified a Finished. That is a much smaller thing to get right than an
// event-driven design, and it matches how the layer is used - a caller
// establishes the connection once and then reads and writes.
//
// Only one cipher suite is implemented: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
// It is what browsers negotiate, it gives forward secrecy, and it matches the
// P-256 certificate this package generates.

// Role decides which side of the handshake to take.
pub enum Role {
	// client sends the first ClientHello. In SDP terms this is a=setup:active.
	client
	// server waits for one. In SDP terms this is a=setup:passive.
	server
}

pub fn (r Role) str() string {
	return match r {
		.client { 'client' }
		.server { 'server' }
	}
}