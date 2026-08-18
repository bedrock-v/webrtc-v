// Ask a STUN server what address the internet sees this machine as.
//
// Run with: v run examples/stun-discover [server:port]
//
// This is the discovery half of what ICE does when it gathers a
// server-reflexive candidate. Note that the answer belongs to the socket that
// asked: a NAT mapping is created for a source port, so this address is only
// usable from the socket the client opened, which is why the ICE agent runs the
// same exchange on each of its own sockets rather than calling this.
module main

import os
import time
import webrtc.logging
import webrtc.stunclient

const default_server = 'stun.l.google.com:19302'

fn main() {
	server := if os.args.len > 1 { os.args[1] } else { default_server }

	println('asking ${server}...')
	started := time.now()

	address := stunclient.discover(server,
		rto:               500 * time.millisecond
		max_transmissions: 5
		logger:            logging.from_env('stun')
	) or {
		eprintln('failed: ${err}')
		exit(1)
	}

	elapsed := time.now() - started
	println('the internet sees this machine as ${address}')
	println('  family:  ${address.ip.family}')
	println('  private: ${address.ip.is_private()}')
	println('  took:    ${elapsed.milliseconds()}ms')

	if address.ip.is_private() {
		println('')
		println('The reflexive address is private, so this machine is either not')
		println('behind a NAT or is behind one that does not translate.')
	}
}
