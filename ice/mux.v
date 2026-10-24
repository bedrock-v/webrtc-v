module ice

import net
import sync
import time
import webrtc.logging
import webrtc.netaddr
import webrtc.stun
import webrtc.transport

// max_mux_remotes bounds how many remote addresses one agent may hold routes
// for. Each authenticated address a peer checks from claims one and a peer
// has no more addresses than it has candidates.
const max_mux_remotes = max_remote_candidates

// max_mux_transactions bounds how many checks one agent may have awaiting a
// response through the mux.
const max_mux_transactions = 256

@[params]
pub struct UdpMuxConfig {
pub:
	port       u16
	interfaces InterfaceOptions
	logger     logging.Logger = logging.nop()
}

// UdpMux lets every agent share one UDP port.
//
// A datagram goes to the agent that claimed its address. Before a claim, a
// Binding request is routed by the ufrag in its USERNAME and a response by its
// transaction ID. Anything else is dropped.
//
// The caller owns the mux and closes it after the agents using it.
@[heap]
pub struct UdpMux {
	port u16
mut:
	mu      &sync.Mutex = sync.new_mutex()
	log     logging.Logger
	sockets []MuxConn
	// routes holds every agent using the mux by local ufrag.
	routes map[string]&MuxRoute
	// claimed maps '<socket>|<remote>' to the agent that proved it owns that
	// path.
	claimed map[string]&MuxRoute
	// checks maps a transaction ID to the agent that sent the request.
	checks map[string]&MuxRoute
	// lookups maps a transaction ID to a reflexive lookup waiting on it.
	lookups map[string]chan []u8
	closed  bool
	threads []thread
}

struct MuxConn {
mut:
	conn &net.UdpConn = unsafe { nil }
	base netaddr.SocketAddr
}

// MuxRoute is one agent's registration.
struct MuxRoute {
	ufrag   string
	inbound chan InboundPacket
	first int
mut:
	claimed      []string
	transactions []string
}

// UdpMux.new binds the port on every local address the interface options
// allow.
pub fn UdpMux.new(config UdpMuxConfig) !&UdpMux {
	if config.port == 0 {
		return AgentError{
			reason: .transport
			detail: 'a UDP mux needs a fixed port'
		}
	}
	addresses := local_interface_addresses(config.interfaces)!
	if addresses.len == 0 {
		return AgentError{
			reason: .no_candidates
			detail: 'no usable local interface addresses'
		}
	}
	mut m := &UdpMux{
		port: config.port
		log:  config.logger.with_scope('ice/mux')
	}
	for address in addresses {
		ensure_port_free(address, config.port) or {
			m.close()
			return err
		}
		conn := bind_udp(address, config.port) or {
			m.close()
			return err
		}
		m.sockets << MuxConn{
			conn: conn
			base: netaddr.SocketAddr.new(address, config.port)
		}
	}
	for i in 0 .. m.sockets.len {
		m.threads << spawn m.read(i)
	}
	return m
}

// ensure_port_free fails when anybody holds the port.
fn ensure_port_free(address netaddr.IpAddr, port u16) ! {
	target := if address.family == .ipv6 { '[${address}]:${port}' } else { '${address}:${port}' }
	family := if address.family == .ipv6 { net.AddrFamily.ip6 } else { net.AddrFamily.ip }
	addrs := net.resolve_addrs(target, family, .udp) or {
		return AgentError{
			reason: .transport
			detail: 'resolving ${target}: ${err.msg()}'
		}
	}
	addr := addrs[0]
	fd := C.socket(i32(addr.family()), i32(net.SocketType.udp), 0)
	if fd < 0 {
		return AgentError{
			reason: .transport
			detail: 'opening a socket to test ${target}'
		}
	}
	defer {
		net.close(fd) or {}
	}
	if C.bind(fd, voidptr(&addr), addr.len()) != 0 {
		return AgentError{
			reason: .transport
			detail: 'UDP port ${target} is already in use'
		}
	}
}

// port is the port every mux socket is bound to.
pub fn (m &UdpMux) port() u16 {
	return m.port
}

// close closes every socket and waits for the readers. Agents still registered
// stop receiving.
pub fn (mut m UdpMux) close() {
	m.mu.lock()
	if m.closed {
		m.mu.unlock()
		return
	}
	m.closed = true
	m.routes.clear()
	m.claimed.clear()
	m.checks.clear()
	mut sockets := m.sockets.clone()
	m.mu.unlock()

	for mut socket in sockets {
		socket.conn.close() or {}
	}
	for handle in m.threads {
		handle.wait()
	}
}

fn (mut m UdpMux) is_closed() bool {
	m.mu.lock()
	defer {
		m.mu.unlock()
	}
	return m.closed
}

// bases are the addresses of the mux sockets in socket order.
fn (m &UdpMux) bases() []netaddr.SocketAddr {
	return m.sockets.map(it.base)
}

// register adds an agent. Its sockets for this mux start at first in its own
// list.
fn (mut m UdpMux) register(ufrag string, inbound chan InboundPacket, first int) ! {
	m.mu.lock()
	defer {
		m.mu.unlock()
	}
	if m.closed {
		return AgentError{
			reason: .closed
			detail: 'the UDP mux is closed'
		}
	}
	if ufrag in m.routes {
		return AgentError{
			reason: .bad_credentials
			detail: 'another agent on this mux uses ufrag "${ufrag}"'
		}
	}
	m.routes[ufrag] = &MuxRoute{
		ufrag:   ufrag
		inbound: inbound
		first:   first
	}
}

// unregister removes an agent and everything routed to it. The agent closes
// its inbound channel only after this, so nothing is delivered to a closed one.
fn (mut m UdpMux) unregister(ufrag string) {
	m.mu.lock()
	defer {
		m.mu.unlock()
	}
	route := m.routes[ufrag] or { return }
	for key in route.claimed {
		if owner := m.claimed[key] {
			if owner == route {
				m.claimed.delete(key)
			}
		}
	}
	for key in route.transactions {
		m.checks.delete(key)
	}
	m.routes.delete(ufrag)
}

// claim routes a remote address to an agent. The agent calls it only once a
// check from that address authenticated.
fn (mut m UdpMux) claim(ufrag string, socket int, remote netaddr.SocketAddr) {
	m.mu.lock()
	defer {
		m.mu.unlock()
	}
	mut route := m.routes[ufrag] or { return }
	key := '${socket}|${remote}'
	if mut previous := m.claimed[key] {
		if previous == route {
			return
		}
		previous.claimed = previous.claimed.filter(it != key)
		m.log.debug('${remote} moved to another connection')
	}
	if route.claimed.len >= max_mux_remotes {
		m.claimed.delete(route.claimed[0])
		route.claimed.delete(0)
	}
	route.claimed << key
	m.claimed[key] = route
}

// expect routes the response to a request the agent is about to send.
fn (mut m UdpMux) expect(ufrag string, transaction string) {
	m.mu.lock()
	defer {
		m.mu.unlock()
	}
	mut route := m.routes[ufrag] or { return }
	if route.transactions.len >= max_mux_transactions {
		m.checks.delete(route.transactions[0])
		route.transactions.delete(0)
	}
	route.transactions << transaction
	m.checks[transaction] = route
}

// forget drops a transaction the agent no longer waits on.
fn (mut m UdpMux) forget(ufrag string, transaction string) {
	m.mu.lock()
	defer {
		m.mu.unlock()
	}
	mut route := m.routes[ufrag] or { return }
	m.checks.delete(transaction)
	route.transactions = route.transactions.filter(it != transaction)
}

// write_to sends a datagram out of one of the mux sockets.
fn (mut m UdpMux) write_to(socket int, to netaddr.SocketAddr, data []u8) !int {
	if socket < 0 || socket >= m.sockets.len {
		return AgentError{
			reason: .wrong_state
			detail: 'no mux socket ${socket}'
		}
	}
	destination := transport.socket_addr_to_net(to) or {
		return AgentError{
			reason: .transport
			detail: err.msg()
		}
	}
	mut conn := m.sockets[socket].conn
	return conn.write_to(destination, data) or {
		return AgentError{
			reason: .transport
			detail: 'send to ${to}: ${err.msg()}'
		}
	}
}

// lookup asks a STUN server what address a mux socket is seen from. The
// response is matched by transaction ID since every agent on the mux reads the
// same socket.
fn (mut m UdpMux) lookup(socket int, server netaddr.SocketAddr) !netaddr.SocketAddr {
	mut request := stun.Message.new(.request, .binding)!
	raw := request.encode(fingerprint: true)!
	key := request.transaction_id[..].hex()
	responses := chan []u8{cap: 1}

	m.mu.lock()
	m.lookups[key] = responses
	m.mu.unlock()
	defer {
		m.mu.lock()
		m.lookups.delete(key)
		m.mu.unlock()
	}

	deadline := time.now().add(gather_timeout)
	mut attempt := 0
	for time.now() < deadline {
		attempt++
		m.write_to(socket, server, raw)!
		// Retransmit on a doubling schedule, bounded by the overall deadline.
		mut wait := 100 * time.millisecond * i64(1 << (attempt - 1))
		if time.now().add(wait) > deadline {
			wait = deadline - time.now()
		}
		select {
			data := <-responses {
				response := stun.Message.decode(data)!
				if response.typ.class != .success_response {
					return AgentError{
						reason: .transport
						detail: 'STUN server answered with ${response.typ.class}'
					}
				}
				return response.reflexive_address()!
			}
			wait {}
		}
	}
	return AgentError{
		reason: .timed_out
		detail: 'no Binding response within ${gather_timeout.milliseconds()}ms'
	}
}

// read sorts what arrives on one mux socket.
fn (mut m UdpMux) read(index int) {
	mut conn := m.sockets[index].conn
	for {
		if m.is_closed() {
			return
		}
		conn.set_read_timeout(200 * time.millisecond)
		mut buf := []u8{len: max_datagram}
		n, peer := conn.read(mut buf) or { continue }
		if n <= 0 {
			continue
		}
		from := transport.socket_addr_from_net(peer) or { continue }
		m.route(index, from.unmap(), buf[..n].clone())
	}
}

fn (mut m UdpMux) route(index int, from netaddr.SocketAddr, data []u8) {
	// Route STUN by credentials first. Reconnecting peers may still have
	// their address claimed by an old agent.
	// Decode before locking to minimize time spent holding the shared lock.
	mut message := ?stun.Message(none)
	if stun.is_message(data) {
		message = stun.Message.decode(data) or { return }
	}

	m.mu.lock()
	defer {
		m.mu.unlock()
	}
	if m.closed {
		return
	}
	if msg := message {
		key := msg.transaction_id[..].hex()
		match msg.typ.class {
			.request {
				if msg.typ.method == .binding {
					if username := msg.username() {
						if route := m.routes[username.all_before(':')] {
							m.deliver(route, index, from, data)
							return
						}
					}
				}
			}
			.success_response, .error_response {
				if responses := m.lookups[key] {
					select {
						responses <- data {}
						else {}
					}
					return
				}
				if route := m.checks[key] {
					m.deliver(route, index, from, data)
					return
				}
			}
			.indication {}
		}
	}
	// Everything else only follows a claim, which an agent makes only for a
	// path that authenticated.
	if route := m.claimed['${index}|${from}'] {
		m.deliver(route, index, from, data)
	}
}

// deliver hands a datagram to an agent.
fn (mut m UdpMux) deliver(route &MuxRoute, index int, from netaddr.SocketAddr, data []u8) {
	packet := InboundPacket{
		socket: route.first + index
		from:   from
		data:   data
	}
	select {
		route.inbound <- packet {}
		else {
			m.log.warn('inbound queue full, dropped ${data.len} bytes from ${from}')
		}
	}
}
