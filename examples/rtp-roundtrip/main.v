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

fn main() {
	profile := srtp.Profile.aead_aes_128_gcm
	println('profile: ${profile}')
	println('  master key:  ${profile.master_key_len()} bytes')
	println('  master salt: ${profile.master_salt_len()} bytes')
	println('  tag:         ${profile.rtp_auth_tag_len()} bytes')
	println('')

	// One key per direction. Sharing a context between directions would make
	// both sides produce the same keystream for the same packet index, which is
	// a complete break of confidentiality.
	material := []u8{len: profile.keying_material_len(), init: u8(index * 7 + 3)}
	sender_keys, receiver_keys := srtp.split_keying_material(material, profile)!

	mut sender := srtp.Context.from_keying_material(sender_keys, profile)!
	mut receiver := srtp.Context.from_keying_material(sender_keys, profile)!
	// receiver_keys would key the reverse direction; unused in this one-way
	// example.
	_ := receiver_keys

	mut sequencer := rtp.Sequencer.new()!
	ssrc := u32(0xCAFEBABE)

	for i in 0 .. 3 {
		payload := 'frame ${i}'.bytes()

		mut packet := rtp.Packet{
			header:  rtp.Header{
				payload_type:    96
				sequence_number: sequencer.next()
				timestamp:       u32(90000 * i)
				ssrc:            ssrc
				marker:          i == 0
			}
			payload: payload
		}
		// A one-byte header extension, as negotiated by an SDP extmap.
		packet.header.set_extension(1, [u8(0x80)])!

		plain := packet.marshal()!
		protected := sender.protect_rtp(plain)!

		println('packet ${i}: seq=${packet.header.sequence_number} ${plain.len} bytes -> ${protected.len} protected')
		println('  header stays readable: ${protected[..12].hex()}')
		println('  payload is encrypted:  ${protected[16..24].hex()}')

		recovered := receiver.unprotect_rtp(protected)!
		decoded := rtp.Packet.decode(recovered)!
		println('  recovered: "${decoded.payload.bytestr()}" ext=${decoded.header.extension(1)?.hex()}')
	}

	// Replaying a packet is rejected, because its index has already been seen.
	println('')
	replayed := protect_one(mut sender, ssrc, sequencer.next())!
	receiver.unprotect_rtp(replayed)!
	receiver.unprotect_rtp(replayed) or { println('replay correctly rejected: ${err}') }

	// A tampered packet fails authentication before it is decrypted. It has to
	// be a packet the receiver has not seen: RFC 3711 checks the replay window
	// first, so tampering with an already-accepted packet is caught as a replay
	// and never reaches the tag check.
	mut tampered := protect_one(mut sender, ssrc, sequencer.next())!
	tampered[tampered.len - 1] ^= 0x01
	receiver.unprotect_rtp(tampered) or { println('tampering correctly rejected: ${err}') }

	// RTCP goes over the same transport, protected with its own keys.
	println('')
	report := rtcp.ReceiverReport{
		ssrc:    ssrc
		reports: [
			rtcp.ReceptionReport{
				ssrc:                 0x11223344
				fraction_lost:        13
				total_lost:           42
				last_sequence_number: 1234
				jitter:               99
			},
		]
	}
	control := rtcp.marshal([rtcp.Packet(report)])!
	protected_control := sender.protect_rtcp(control)!
	println('rtcp: ${control.len} bytes -> ${protected_control.len} protected')

	decoded_control := rtcp.unmarshal(receiver.unprotect_rtcp(protected_control)!)!
	rr := decoded_control[0] as rtcp.ReceiverReport
	println('  reported ${rr.reports[0].total_lost} lost, jitter ${rr.reports[0].jitter}')
}
