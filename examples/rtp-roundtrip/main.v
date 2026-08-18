// Build an RTP packet, protect it with SRTP, and take it apart again.
//
// Run with: v run examples/rtp-roundtrip
//
// The keys here are made up. In a real connection they come from the DTLS
// handshake through the extractor of RFC 5764, and are split into the two
// directions with srtp.split_keying_material.
module main