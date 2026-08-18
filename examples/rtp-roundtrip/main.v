// Build an RTP packet, protect it with SRTP, and take it apart again.
//
// Run with: v run examples/rtp-roundtrip
//
// The keys here are made up. In a real connection they come from the DTLS
// handshake through the extractor of RFC 5764, and are split into the two
// directions with srtp.split_keying_material.
module main

import webrtc.rtcp
import webrtc.rtp
import webrtc.srtp

// protect_one builds a one-byte packet and protects it, for the demonstrations
// below that only care about the wire form.
fn protect_one(mut context srtp.Context, ssrc u32, sequence u16) ![]u8 {
	packet := rtp.Packet{
		header:  rtp.Header{
			payload_type:    96
			sequence_number: sequence
			ssrc:            ssrc
		}
		payload: 'x'.bytes()
	}
	return context.protect_rtp(packet.marshal()!)!
}