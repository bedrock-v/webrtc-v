// The same connection as examples/datachannel, through the PeerConnection API.
//
// Run with: v run examples/peer-connection
//
// Two peers exchange an offer, an answer and their candidates - the four things
// a real deployment would push through its signalling channel - and everything
// below that is handled for them: ICE, DTLS, SCTP, the data channel roles and
// the stream identifiers.
module main

import time
import webrtc
import webrtc.logging

fn main() {
	log := logging.from_env('example')
	started := time.now()

	mut caller := webrtc.PeerConnection.new(logger: log.with_scope('caller'))!
	mut callee := webrtc.PeerConnection.new(logger: log.with_scope('callee'))!
	defer {
		caller.close()
		callee.close()
	}

	// A channel created now is opened for us once the transports are up.
	mut chat := caller.create_data_channel('chat')!

	// --- Signalling -------------------------------------------------------
	offer := caller.create_offer()!
	caller.set_local_description(offer)!
	callee.set_remote_description(offer)!

	answer := callee.create_answer()!
	callee.set_local_description(answer)!
	caller.set_remote_description(answer)!

	for line in caller.local_candidates() {
		callee.add_ice_candidate(line) or {}
	}
	for line in callee.local_candidates() {
		caller.add_ice_candidate(line) or {}
	}
	println('signalled in ${elapsed(started)}')

	// --- Connecting -------------------------------------------------------
	caller.wait_connected(30 * time.second)!
	callee.wait_connected(30 * time.second)!
	println('connected in ${elapsed(started)}')
	println('caller: ${caller.statistics()}')

	// --- Talking ----------------------------------------------------------
	mut inbox := callee.accept_data_channel(10 * time.second)!
	println('the callee was offered the channel "${inbox.label}"')

	for index in 0 .. 5 {
		chat.send_text('hello ${index}')!
	}
	for _ in 0 .. 5 {
		message := inbox.recv(5 * time.second)!
		println('callee received: ${message.text()}')
	}

	inbox.send_text('goodbye')!
	reply := chat.recv(5 * time.second)!
	println('caller received: ${reply.text()}')

	// A large binary message is fragmented over SCTP and reassembled, which is
	// what makes a data channel usable for more than chat.
	payload := []u8{len: 64 * 1024, init: u8(index & 0xff)}
	chat.send_binary(payload)!
	blob := inbox.recv(10 * time.second)!
	println('callee received ${blob.data.len} bytes, intact: ${blob.data == payload}')

	println('done in ${elapsed(started)}')
}