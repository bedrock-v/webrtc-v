// How fast a data channel actually goes, over real sockets.
//
// Run with: make bench    (or: v -prod run examples/throughput)
//
// Build this one with -prod. V's default build is unoptimised, and the whole
// stack is CPU-bound on AES, so a debug build measures the compiler rather than
// the code - by roughly a factor of three.
module main

import time
import webrtc
import webrtc.logging

const message_size = 16 * 1024

const message_count = 512

fn main() {
	log := logging.from_env('bench')

	mut caller := webrtc.PeerConnection.new(logger: log)!
	mut callee := webrtc.PeerConnection.new(logger: log)!
	defer {
		caller.close()
		callee.close()
	}

	mut sender := caller.create_data_channel('bench')!
	negotiate(mut caller, mut callee)!
	caller.wait_connected(30 * time.second)!
	callee.wait_connected(30 * time.second)!
	mut receiver := callee.accept_data_channel(10 * time.second)!

	payload := []u8{len: message_size, init: u8(index & 0xff)}
	started := time.now()
	spawn fn [payload] (mut channel webrtc.DataChannel) {
		for _ in 0 .. message_count {
			channel.send_binary(payload) or { break }
		}
	}(mut sender)

	mut received := 0
	for received < message_count {
		receiver.recv(60 * time.second) or { break }
		received++
	}
	took := time.now() - started

	total := received * message_size
	rate := f64(total) / took.seconds() / 1024 / 1024
	println('${received}/${message_count} messages of ${message_size} bytes')
	println('${total} bytes in ${took.milliseconds()}ms = ${rate:.1f} MB/s')
	println('')
	println('caller: ${caller.statistics()}')
}

fn negotiate(mut caller webrtc.PeerConnection, mut callee webrtc.PeerConnection) ! {
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
}
