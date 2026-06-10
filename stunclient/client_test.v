module stunclient

import net
import sync
import time
import webrtc.stun
import webrtc.transport

// A minimal in-process STUN server. Running the client against a real socket
// exercises encoding, the transaction match, the read deadline and the
// retransmission loop together, which unit tests over byte slices cannot.
struct TestServer {
mut:
	conn &net.UdpConn
	mu   &sync.Mutex = sync.new_mutex()
	// drop_first makes the server ignore the given number of requests, forcing
	// the client to retransmit.
	drop_first int
	// reply_wrong_tid makes the server answer with a transaction id the client
	// never used, which it must ignore.
	reply_wrong_tid bool
	// reply_error makes the server answer with a 400 error response.
	reply_error bool
	stopped     bool
pub:
	addr string
}