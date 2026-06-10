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

fn start_test_server() !&TestServer {
	mut conn := net.listen_udp(':0')!
	bound := transport.local_addr(conn)!
	return &TestServer{
		conn: conn
		addr: '127.0.0.1:${bound.port}'
	}
}

fn (mut s TestServer) serve() {
	for {
		s.mu.lock()
		if s.stopped {
			s.mu.unlock()
			return
		}
		s.mu.unlock()

		s.conn.set_read_timeout(50 * time.millisecond)
		mut buf := []u8{len: 1500}
		n, peer := s.conn.read(mut buf) or { continue }

		req := stun.Message.decode(buf[..n]) or { continue }

		s.mu.lock()
		if s.drop_first > 0 {
			s.drop_first--
			s.mu.unlock()
			continue
		}
		wrong_tid := s.reply_wrong_tid
		as_error := s.reply_error
		s.mu.unlock()

		source := transport.socket_addr_from_net(peer) or { continue }
		mut resp := if wrong_tid {
			stun.Message.new(.success_response, .binding) or { continue }
		} else if as_error {
			stun.Message.response(req, .error_response)
		} else {
			stun.Message.response(req, .success_response)
		}

		if as_error {
			resp.add_error_code(stun.code_bad_request, '') or { continue }
		} else {
			resp.add_xor_mapped_address(source) or { continue }
		}
		raw := resp.encode(fingerprint: true) or { continue }
		s.conn.write_to(peer, raw) or { continue }
	}
}