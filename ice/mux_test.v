module ice

import net
import time
import webrtc.netaddr
import webrtc.stun
import webrtc.transport

const mux_loopback = InterfaceOptions{
	interfaces:       ['lo']
	include_loopback: true
	include_ipv6:     false
}

fn free_udp_port() u16 {
	mut probe := net.listen_udp('127.0.0.1:0') or { panic(err) }
	addr := transport.local_addr(probe) or { panic(err) }
	probe.close() or {}
	return addr.port
}

fn new_mux() !&UdpMux {
	return UdpMux.new(port: free_udp_port(), interfaces: mux_loopback)!
}

fn connect_through_mux(mut mux UdpMux, peer_ports ?&PortPool) !(&Agent, &Agent) {
	mut served := Agent.new(
		role:           .controlled
		udp_mux:        mux
		check_interval: 10 * time.millisecond
	)!
	mut peer := Agent.new(
		role:           .controlling
		interfaces:     mux_loopback
		port_pool:      peer_ports
		check_interval: 10 * time.millisecond
	)!
	s_ufrag, s_pwd := served.local_credentials()
	p_ufrag, p_pwd := peer.local_credentials()
	served.set_remote_credentials(p_ufrag, p_pwd)!
	peer.set_remote_credentials(s_ufrag, s_pwd)!
	served.gather()!
	peer.gather()!
	for candidate in served.local_candidates() {
		peer.add_remote_candidate(candidate)!
	}
	for candidate in peer.local_candidates() {
		served.add_remote_candidate(candidate)!
	}
	served.connect(10 * time.second)!
	peer.connect(10 * time.second)!
	return served, peer
}

fn exchange(mut served Agent, mut peer Agent, text string) ! {
	peer.send(text.bytes())!
	assert served.recv(5 * time.second)!.bytestr() == text
	served.send('re: ${text}'.bytes())!
	assert peer.recv(5 * time.second)!.bytestr() == 're: ${text}'
}

fn test_mux_serves_two_agents_on_one_port() {
	$if !linux {
		return
	}
	mut mux := new_mux()!
	defer {
		mux.close()
	}
	mut a, mut a_peer := connect_through_mux(mut mux, none)!
	mut b, mut b_peer := connect_through_mux(mut mux, none)!
	defer {
		a.close()
		a_peer.close()
		b.close()
		b_peer.close()
	}
	assert a.local_candidates().all(it.address.port == mux.port())
	assert b.local_candidates().all(it.address.port == mux.port())

	exchange(mut a, mut a_peer, 'to a')!
	exchange(mut b, mut b_peer, 'to b')!
}

fn test_closing_one_agent_leaves_the_other_on_the_mux() {
	$if !linux {
		return
	}
	mut mux := new_mux()!
	defer {
		mux.close()
	}
	mut a, mut a_peer := connect_through_mux(mut mux, none)!
	mut b, mut b_peer := connect_through_mux(mut mux, none)!
	defer {
		a_peer.close()
		b.close()
		b_peer.close()
	}
	a.close()
	assert mux.routes.len == 1
	exchange(mut b, mut b_peer, 'still here')!
}

fn test_mux_refuses_a_port_in_use() {
	$if !linux {
		return
	}
	port := free_udp_port()
	mut held := net.listen_udp('127.0.0.1:${port}')!
	defer {
		held.close() or {}
	}
	if mut mux := UdpMux.new(port: port, interfaces: mux_loopback) {
		mux.close()
		assert false, 'the mux bound a port somebody else holds'
	}
}

fn test_unauthenticated_check_claims_no_path() {
	$if !linux {
		return
	}
	mut mux := new_mux()!
	defer {
		mux.close()
	}
	mut agent := Agent.new(role: .controlled, udp_mux: mux)!
	defer {
		agent.close()
	}
	ufrag, _ := agent.local_credentials()
	agent.set_remote_credentials('peer', 'a-password-long-enough-for-ice')!
	agent.gather()!

	mut request := stun.Message.new(.request, .binding)!
	request.add_username('${ufrag}:peer')!
	key := stun.short_term_key('not-the-agents-password-at-all')!
	raw := request.encode(integrity_key: key, fingerprint: true)!

	mut attacker := net.listen_udp('127.0.0.1:0')!
	defer {
		attacker.close() or {}
	}
	attacker.write_to(net.resolve_addrs('127.0.0.1:${mux.port()}', .ip, .udp)![0], raw)!
	time.sleep(300 * time.millisecond)

	mux.mu.lock()
	claimed := mux.claimed.len
	mux.mu.unlock()
	assert claimed == 0, 'a forged check claimed a path'
}

// StunResponder answers every Binding request with one fixed mapped address
// as a STUN server in front of a NAT would.
struct StunResponder {
mut:
	conn   &net.UdpConn
	mapped netaddr.SocketAddr
	done   bool
}

fn (mut r StunResponder) run() {
	for !r.done {
		r.conn.set_read_timeout(100 * time.millisecond)
		mut buf := []u8{len: 2048}
		n, from := r.conn.read(mut buf) or { continue }
		request := stun.Message.decode(buf[..n]) or { continue }
		mut response := stun.Message.response(request, .success_response)
		response.add_xor_mapped_address(r.mapped) or { continue }
		raw := response.encode(fingerprint: true) or { continue }
		r.conn.write_to(from, raw) or {}
	}
}

fn test_reflexive_lookups_through_the_mux_reach_their_agent() {
	$if !linux {
		return
	}
	mut mux := new_mux()!
	defer {
		mux.close()
	}
	mut responder := &StunResponder{
		conn:   net.listen_udp('127.0.0.1:0')!
		mapped: netaddr.SocketAddr.parse('203.0.113.5:4000')!
	}
	server := transport.local_addr(responder.conn)!
	worker := spawn responder.run()
	defer {
		responder.done = true
		worker.wait()
		responder.conn.close() or {}
	}

	mut agents := []&Agent{}
	for _ in 0 .. 2 {
		agents << Agent.new(udp_mux: mux, stun_servers: [server.str()])!
	}
	defer {
		for mut agent in agents {
			agent.close()
		}
	}
	mut threads := []thread !{}
	for mut agent in agents {
		threads << spawn agent.gather()
	}
	for t in threads {
		t.wait()!
	}
	for mut agent in agents {
		assert agent.local_candidates().any(it.typ == .server_reflexive
			&& it.address.str() == '203.0.113.5:4000')
	}
}

fn test_reconnect_from_a_claimed_addr_reaches_the_new_agent() {
	$if !linux {
		return
	}
	mut mux := new_mux()!
	defer {
		mux.close()
	}
	port := free_udp_port()
	pool := PortPool.new(port, port)!
	mut old, mut old_peer := connect_through_mux(mut mux, pool)!
	defer {
		old.close()
	}
	old_peer.close()

	mut fresh, mut fresh_peer := connect_through_mux(mut mux, pool)!
	defer {
		fresh.close()
		fresh_peer.close()
	}
	exchange(mut fresh, mut fresh_peer, 'back again')!
}
