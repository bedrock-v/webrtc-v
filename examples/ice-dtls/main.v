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

import time
import webrtc.dtls
import webrtc.ice
import webrtc.logging
import webrtc.rtp

fn main() {
	log := logging.from_env('example')

	// --- Identities -------------------------------------------------------
	// Each side generates a certificate and publishes its fingerprint. That
	// fingerprint is the only thing authenticating the peer: DTLS checks the
	// certificate presented in the handshake against it, and there is no
	// certificate authority anywhere in the picture.
	caller_certificate := dtls.Certificate.generate()!
	callee_certificate := dtls.Certificate.generate()!
	caller_fingerprint := caller_certificate.fingerprint(.sha256)
	callee_fingerprint := callee_certificate.fingerprint(.sha256)

	println('caller a=fingerprint:${caller_fingerprint}')
	println('callee a=fingerprint:${callee_fingerprint}')
	println('')

	// --- ICE --------------------------------------------------------------
	interfaces := ice.InterfaceOptions{
		include_loopback: true
	}
	mut caller_ice := ice.Agent.new(
		role:           .controlling
		interfaces:     interfaces
		check_interval: 20 * time.millisecond
		logger:         log.with_scope('caller')
	)!
	defer {
		caller_ice.close()
	}
	mut callee_ice := ice.Agent.new(
		role:           .controlled
		interfaces:     interfaces
		check_interval: 20 * time.millisecond
		logger:         log.with_scope('callee')
	)!
	defer {
		callee_ice.close()
	}

	caller_ufrag, caller_pwd := caller_ice.local_credentials()
	callee_ufrag, callee_pwd := callee_ice.local_credentials()
	caller_ice.set_remote_credentials(callee_ufrag, callee_pwd)!
	callee_ice.set_remote_credentials(caller_ufrag, caller_pwd)!

	caller_ice.gather()!
	callee_ice.gather()!
	for candidate in caller_ice.local_candidates() {
		callee_ice.add_remote_candidate(candidate)!
	}
	for candidate in callee_ice.local_candidates() {
		caller_ice.add_remote_candidate(candidate)!
	}

	started := time.now()
	caller_ice.connect(20 * time.second)!
	callee_ice.connect(20 * time.second)!
	println('ICE connected in ${(time.now() - started).milliseconds()}ms')
	if pair := caller_ice.selected_pair() {
		println('  path: ${pair.local.address} -> ${pair.remote.address}')
		println('  round trip: ${pair.round_trip_time.microseconds()}us')
	}
	println('')

	// --- DTLS -------------------------------------------------------------
	// The ICE agent is the transport. Which side takes the client role comes
	// from the a=setup attribute in a real session; here the controlling agent
	// takes it.
	mut caller_dtls := dtls.Conn.new(caller_ice,
		role:                .client
		certificate:         caller_certificate
		remote_fingerprints: [callee_fingerprint]
		logger:              log.with_scope('caller')
	)!
	mut callee_dtls := dtls.Conn.new(callee_ice,
		role:                .server
		certificate:         callee_certificate
		remote_fingerprints: [caller_fingerprint]
		logger:              log.with_scope('callee')
	)!

	handshake_started := time.now()
	server_thread := spawn fn (mut c dtls.Conn) ! {
		c.handshake()!
	}(mut callee_dtls)
	caller_dtls.handshake()!
	server_thread.wait()!

	println('DTLS handshake completed in ${(time.now() - handshake_started).milliseconds()}ms')
	println('  caller: ${caller_dtls.state()} as ${caller_dtls.role()}')
	println('  callee: ${callee_dtls.state()} as ${callee_dtls.role()}')
	if profile := caller_dtls.selected_srtp_profile() {
		println('  negotiated SRTP profile: ${profile}')
	}
	println('')

	// --- Application data over DTLS ---------------------------------------
	caller_dtls.write('secure hello'.bytes())!
	println('callee received over DTLS: "${callee_dtls.read(5 * time.second)!.bytestr()}"')
	callee_dtls.write('secure reply'.bytes())!
	println('caller received over DTLS: "${caller_dtls.read(5 * time.second)!.bytestr()}"')
	println('')

	// --- SRTP -------------------------------------------------------------
	// The handshake exported keying material; each side splits it into the two
	// directions. Media does not go inside the DTLS records - it is protected
	// with these keys and sent over the same ICE path.
	mut caller_out, mut caller_in := caller_dtls.srtp_contexts()!
	mut callee_out, mut callee_in := callee_dtls.srtp_contexts()!

	mut sequencer := rtp.Sequencer.new()!
	packet := rtp.Packet{
		header:  rtp.Header{
			payload_type:    96
			sequence_number: sequencer.next()
			timestamp:       90000
			ssrc:            0xCAFEBABE
			marker:          true
		}
		payload: 'a video frame'.bytes()
	}
	plain := packet.marshal()!
	protected := caller_out.protect_rtp(plain)!
	println('RTP: ${plain.len} bytes -> ${protected.len} protected')
	println('  header stays readable: ${protected[..12].hex()}')

	recovered := rtp.Packet.decode(callee_in.unprotect_rtp(protected)!)!
	println('  callee recovered: "${recovered.payload.bytestr()}" seq=${recovered.header.sequence_number}')

	// And the same in the other direction, which is the check that the client
	// and server halves of the keying material went to the right places.
	reply := callee_out.protect_rtp(plain)!
	assert caller_in.unprotect_rtp(reply)! == plain
	println('  reverse direction verified')

	// A tampered packet fails authentication. It has to be a packet the
	// receiver has not seen: the replay window is consulted before the tag, so
	// editing an already-accepted packet is caught as a replay instead.
	println('')
	println('A tampered packet is rejected:')
	fresh := rtp.Packet{
		header:  rtp.Header{
			payload_type:    96
			sequence_number: sequencer.next()
			ssrc:            0xCAFEBABE
		}
		payload: 'another frame'.bytes()
	}
	mut tampered := caller_out.protect_rtp(fresh.marshal()!)!
	tampered[tampered.len - 1] ^= 0x01
	callee_in.unprotect_rtp(tampered) or { println('  ${err}') }

	if profile := caller_dtls.selected_srtp_profile() {
		println('')
		println('${profile}: ${profile.master_key_len()}-byte key, ${profile.rtp_auth_tag_len()}-byte tag per packet')
	}
}
