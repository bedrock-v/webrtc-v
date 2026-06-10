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

fn (mut s TestServer) stop() {
	s.mu.lock()
	s.stopped = true
	s.mu.unlock()
	s.conn.close() or {}
}

fn test_client_binding_against_live_server() {
	mut server := start_test_server()!
	handle := spawn server.serve()
	defer {
		server.stop()
		handle.wait()
	}

	addr := discover(server.addr, rto: 200 * time.millisecond, max_transmissions: 3)!
	assert addr.ip.is_loopback()
	assert addr.port != 0
}

fn test_client_retransmits_until_answered() {
	mut server := start_test_server()!
	server.drop_first = 2
	handle := spawn server.serve()
	defer {
		server.stop()
		handle.wait()
	}

	mut client := Client.dial(server.addr, rto: 100 * time.millisecond, max_transmissions: 5)!
	defer {
		client.close()
	}

	addr := client.binding()!
	assert addr.ip.is_loopback()
}

fn test_client_ignores_mismatched_transaction_id() {
	mut server := start_test_server()!
	server.reply_wrong_tid = true
	handle := spawn server.serve()
	defer {
		server.stop()
		handle.wait()
	}

	mut client := Client.dial(server.addr, rto: 60 * time.millisecond, max_transmissions: 2)!
	defer {
		client.close()
	}

	client.binding() or {
		assert err is TimeoutError, 'expected a timeout, got ${err}'
		return
	}
	assert false, 'a response with the wrong transaction id must not satisfy the request'
}

fn test_client_surfaces_error_response() {
	mut server := start_test_server()!
	server.reply_error = true
	handle := spawn server.serve()
	defer {
		server.stop()
		handle.wait()
	}

	mut client := Client.dial(server.addr, rto: 200 * time.millisecond, max_transmissions: 2)!
	defer {
		client.close()
	}

	client.binding() or {
		assert err.code() == stun.code_bad_request, 'expected a 400, got ${err}'
		return
	}
	assert false, 'an error response must be surfaced as an error'
}

fn test_client_times_out_against_a_silent_server() {
	// A socket nobody is listening on: the request goes nowhere.
	mut conn := net.listen_udp(':0')!
	port := transport.local_addr(conn)!.port
	conn.close()!

	started := time.now()
	mut client := Client.dial('127.0.0.1:${port}',
		rto:               50 * time.millisecond
		max_transmissions: 3
	)!
	defer {
		client.close()
	}

	client.binding() or {
		assert err is TimeoutError
		if err is TimeoutError {
			assert err.transmissions == 3
		}
		// 50 + 100 + 200 ms of backoff; allow generous slack for slow CI.
		elapsed := time.now() - started
		assert elapsed >= 300 * time.millisecond
		assert elapsed < 10 * time.second
		return
	}
	assert false, 'expected a timeout'
}

fn test_client_rejects_invalid_config() {
	Client.dial('127.0.0.1:1', max_transmissions: 0) or {
		Client.dial('127.0.0.1:1', rto: 0) or { return }
		assert false, 'a non-positive rto must be rejected'
	}
	assert false, 'a zero transmission count must be rejected'
}