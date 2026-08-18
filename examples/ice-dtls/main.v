// Establish a secure media path the way WebRTC does: ICE finds a route, DTLS
// authenticates the peers over it, and the handshake exports the keys that
// protect the media.
//
// Run with: v run examples/ice-dtls
//
// Both endpoints live in this process. Everything they exchange directly -
// ICE credentials and candidates, and the DTLS certificate fingerprints - is
// what a real deployment sends through its signalling channel. Nothing else
// passes between them: the transport is real UDP, and the DTLS handshake runs
// over whichever candidate pair ICE selected.
module main