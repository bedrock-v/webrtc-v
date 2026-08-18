// The whole WebRTC data channel path, end to end over real sockets.
//
// Run with: v run examples/datachannel
//
// ICE finds a route, DTLS authenticates the peers over it, SCTP runs inside the
// DTLS connection, and a data channel is one SCTP stream pair. Both endpoints
// live in this process; everything they exchange directly - ICE credentials and
// candidates, and the DTLS fingerprints - is what a real deployment sends
// through its signalling channel.
module main

import time
import webrtc.datachannel
import webrtc.dtls
import webrtc.ice
import webrtc.logging
import webrtc.sctp

fn main() {
	log := logging.from_env('example')
	started := time.now()

	// --- Signalling -------------------------------------------------------
	caller_certificate := dtls.Certificate.generate()!
	callee_certificate := dtls.Certificate.generate()!
	caller_fingerprint := caller_certificate.fingerprint(.sha256)
	callee_fingerprint := callee_certificate.fingerprint(.sha256)

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

	// --- ICE --------------------------------------------------------------
	caller_ice.connect(20 * time.second)!
	callee_ice.connect(20 * time.second)!
	println('ICE connected           ${elapsed(started)}')
	if pair := caller_ice.selected_pair() {
		println('  path ${pair.local.address} -> ${pair.remote.address}, rtt ${pair.round_trip_time.microseconds()}us')
	}

	// --- DTLS -------------------------------------------------------------
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

	dtls_thread := spawn fn (mut c dtls.Conn) ! {
		c.handshake()!
	}(mut callee_dtls)
	caller_dtls.handshake()!
	dtls_thread.wait()!
	println('DTLS handshake done     ${elapsed(started)}')
	println('  peer authenticated against the signalled fingerprint')

	// --- SCTP -------------------------------------------------------------
	// RFC 8841 makes the DTLS client the SCTP client, so the role passes
	// straight through.
	mut caller_sctp := sctp.Association.new(caller_dtls,
		role:   .client
		logger: log.with_scope('caller')
	)!
	defer {
		caller_sctp.close()
	}
	mut callee_sctp := sctp.Association.new(callee_dtls,
		role:   .server
		logger: log.with_scope('callee')
	)!
	defer {
		callee_sctp.close()
	}

	sctp_thread := spawn fn (mut a sctp.Association) ! {
		a.connect(20 * time.second)!
	}(mut callee_sctp)
	caller_sctp.connect(20 * time.second)!
	sctp_thread.wait()!
	println('SCTP associated         ${elapsed(started)}')

	// --- Data channels ----------------------------------------------------
	mut caller_channels := datachannel.Manager.new(caller_sctp,
		is_dtls_client: true
		logger:         log.with_scope('caller')
	)
	defer {
		caller_channels.close()
	}
	mut callee_channels := datachannel.Manager.new(callee_sctp,
		is_dtls_client: false
		logger:         log.with_scope('callee')
	)
	defer {
		callee_channels.close()
	}

	mut chat := caller_channels.create('chat', datachannel.ChannelOptions{}, 10 * time.second)!
	mut accepted := callee_channels.accept(10 * time.second)!
	println('data channel open       ${elapsed(started)}')
	println('  label "${accepted.label}" on stream ${accepted.stream_identifier}, ordered=${accepted.ordered()} reliable=${accepted.reliable()}')
	println('')

	// --- Traffic ----------------------------------------------------------
	chat.send_text('hello from the caller')!
	println('callee received: "${accepted.recv(5 * time.second)!.text()}"')

	accepted.send_text('and hello back')!
	println('caller received: "${chat.recv(5 * time.second)!.text()}"')

	// Ordering is preserved on a reliable ordered channel, whatever the network
	// did to the packets carrying it.
	for i in 0 .. 10 {
		chat.send_text('ordered ${i}')!
	}
	mut in_order := true
	for i in 0 .. 10 {
		if accepted.recv(5 * time.second)!.text() != 'ordered ${i}' {
			in_order = false
		}
	}
	println('10 messages arrived in order: ${in_order}')

	// A message far larger than the path MTU is fragmented by SCTP and put back
	// together on the other side.
	payload := []u8{len: 60000, init: u8(index % 251)}
	transfer_started := time.now()
	chat.send_binary(payload)!
	received := accepted.recv(20 * time.second)!
	println('60 KB transferred in ${(time.now() - transfer_started).milliseconds()}ms, intact: ${received.data == payload}')

	// An unordered, partially reliable channel is what a latency-sensitive
	// application asks for: a late message is abandoned rather than blocking
	// the ones behind it.
	mut fast := caller_channels.create('fast', datachannel.ChannelOptions{
		ordered:         false
		max_retransmits: u16(0)
	}, 5 * time.second)!
	mut fast_peer := callee_channels.accept(5 * time.second)!
	fast.send_text('best effort')!
	println('')
	println('second channel "${fast_peer.label}": ordered=${fast_peer.ordered()} reliable=${fast_peer.reliable()}')
	println('  received: "${fast_peer.recv(5 * time.second)!.text()}"')

	println('')
	println('total ${elapsed(started)}')
}