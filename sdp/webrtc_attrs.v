module sdp

// Typed accessors for the attributes WebRTC defines on top of SDP.
//
// They all read from the generic Attribute list rather than from parsed fields,
// so an attribute this implementation does not understand survives a parse and
// re-serialise unchanged. That property matters for renegotiation: dropping an
// attribute the local stack ignores would silently change what the remote peer
// previously agreed to.

// Setup is the DTLS role negotiated by the `a=setup` attribute (RFC 4145,
// applied to DTLS-SRTP by RFC 5763).
pub enum Setup {
	// active: this endpoint will start the DTLS handshake as the client.
	active
	// passive: this endpoint will wait for the peer's ClientHello.
	passive
	// actpass: offered only, meaning "you choose". An answer must never
	// contain it, because it would leave the roles undetermined.
	actpass
	// holdconn: no connection is to be established.
	holdconn
}