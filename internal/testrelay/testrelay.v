module testrelay

import net
import sync
import time
import webrtc.internal.codec
import webrtc.netaddr
import webrtc.stun
import webrtc.transport

// Relayed is one payload a client sent through the relay, with the peer it was
// addressed to and the channel it used, zero for a Send indication.
pub struct Relayed {
pub:
	peer    netaddr.SocketAddr
	data    []u8
	channel u16
}

// Allocation is one client's allocation on the relay.
struct Allocation {
mut:
	client      net.Addr
	relayed     netaddr.SocketAddr
	permissions map[string]bool
	channels    map[u16]string
}

// FakeRelay is a TURN server on a loopback socket. It accepts long-term
// credentials for any username with the password "pass" and forwards between
// the clients it has allocated for.
pub struct FakeRelay {
mut:
	conn   &net.UdpConn = unsafe { nil }
	mu     &sync.Mutex  = sync.new_mutex()
	nonce  string       = 'nonce-one'
	client ?net.Addr

	allocated         bool
	allocate_attempts int
	last_realm        string
	permissions       map[string]bool
	channels          map[u16]string
	// allocations is keyed by the client's transport address.
	// This relay able to forward between two clients rather than merely
	// record what one of them sent.
	allocations map[string]Allocation
	next_port   u16 = 49200

	relayed        chan Relayed = chan Relayed{cap: 16}
	silent         bool
	refusal        int
	refusal_reason string

	closed  bool
	threads []thread
}

const relay_realm = 'webrtc-v.test'

// FakeRelay.start listens on a loopback port and serves until stop.
pub fn FakeRelay.start() !&FakeRelay {
	mut conn := net.listen_udp('127.0.0.1:0')!
	mut relay := &FakeRelay{
		conn: conn
	}
	relay.threads << spawn relay.run()
	return relay
}

// address is where clients reach the relay.
pub fn (mut r FakeRelay) address() string {
	bound := transport.local_addr(r.conn) or { panic(err) }
	return bound.str()
}

// stop closes the socket and waits for the serving thread to exit.
pub fn (mut r FakeRelay) stop() {
	r.mu.lock()
	if r.closed {
		r.mu.unlock()
		return
	}
	r.closed = true
	r.mu.unlock()
	r.conn.close() or {}
	for handle in r.threads {
		handle.wait()
	}
}

// go_silent makes the relay drop everything it receives, that is how an
// unreachable server looks to a client.
pub fn (mut r FakeRelay) go_silent() {
	r.mu.lock()
	r.silent = true
	r.mu.unlock()
}

// refuse_with answers every later authenticated request with code and reason.
pub fn (mut r FakeRelay) refuse_with(code int, reason string) {
	r.mu.lock()
	r.refusal = code
	r.refusal_reason = reason
	r.mu.unlock()
}

// rotate_nonce replaces the nonce, making a request that carries the old one
// stale.
pub fn (mut r FakeRelay) rotate_nonce() {
	r.mu.lock()
	r.nonce = 'nonce-two'
	r.mu.unlock()
}

// allocate_attempts counts the Allocate requests received, authenticated or not.
pub fn (mut r FakeRelay) allocate_attempts() int {
	r.mu.lock()
	defer {
		r.mu.unlock()
	}
	return r.allocate_attempts
}

// last_realm is the realm the most recent authenticated request carried.
pub fn (mut r FakeRelay) last_realm() string {
	r.mu.lock()
	defer {
		r.mu.unlock()
	}
	return r.last_realm
}

// has_permission reports whether any client installed a permission for peer.
pub fn (mut r FakeRelay) has_permission(peer netaddr.SocketAddr) bool {
	r.mu.lock()
	defer {
		r.mu.unlock()
	}
	return r.permissions[peer.str()] or { false }
}

// wait_for_relayed returns the next payload a client sent through the relay.
pub fn (mut r FakeRelay) wait_for_relayed(timeout time.Duration) !Relayed {
	select {
		item := <-r.relayed {
			return item
		}
		timeout {
			return error('nothing was relayed within ${timeout.milliseconds()}ms')
		}
	}
	return error('closed')
}

// deliver_from_peer wraps a payload in a Data indication, which is what a relay
// does for a peer with a permission but no channel.
pub fn (mut r FakeRelay) deliver_from_peer(peer netaddr.SocketAddr, data []u8) ! {
	mut indication := stun.Message.new(.indication, .data)!
	indication.add_xor_peer_address(peer)!
	indication.add_data(data)!
	r.send(indication.encode()!)!
}

// deliver_on_channel sends data to the client as ChannelData on a bound channel.
pub fn (mut r FakeRelay) deliver_on_channel(channel u16, data []u8) ! {
	framed := ChannelData{
		channel: channel
		payload: data
	}.encode()!
	r.send(framed)!
}

fn (mut r FakeRelay) send(data []u8) ! {
	r.mu.lock()
	target := r.client
	r.mu.unlock()
	destination := target or { return error('the client has not been seen yet') }
	r.conn.write_to(destination, data)!
}

fn (mut r FakeRelay) run() {
	for {
		r.mu.lock()
		closed := r.closed
		r.mu.unlock()
		if closed {
			return
		}

		r.conn.set_read_timeout(100 * time.millisecond)
		mut buf := []u8{len: 4096}
		n, from := r.conn.read(mut buf) or { continue }
		if n <= 0 {
			continue
		}
		r.mu.lock()
		r.client = from
		silent := r.silent
		r.mu.unlock()
		if silent {
			continue
		}
		r.handle(buf[..n].clone(), from)
	}
}

fn (mut r FakeRelay) handle(datagram []u8, from net.Addr) {
	if is_channel_data(datagram) {
		framed := decode_channel_data(datagram) or { return }
		r.mu.lock()
		mut peer := r.channels[framed.channel] or { '' }
		if allocation := r.allocations[from.str()] {
			if bound := allocation.channels[framed.channel] {
				peer = bound
			}
		}
		r.mu.unlock()
		if peer == '' {
			return
		}
		address := netaddr.SocketAddr.parse(peer) or { return }
		r.relayed <- Relayed{
			peer:    address
			data:    framed.payload
			channel: framed.channel
		}
		r.forward(address, framed.payload)
		return
	}

	message := stun.Message.decode(datagram) or { return }
	if message.typ.class == .indication {
		if message.typ.method != .send {
			return
		}
		peer := message.xor_peer_address() or { return }
		data := message.data() or { return }
		r.mu.lock()
		permitted := r.permissions[peer.str()] or { false }
		r.mu.unlock()
		if !permitted {
			return
		}
		r.relayed <- Relayed{
			peer: peer
			data: data
		}
		r.forward(peer, data)
		return
	}
	if message.typ.class != .request {
		return
	}
	r.handle_request(message, from)
}

fn (mut r FakeRelay) handle_request(message stun.Message, from net.Addr) {
	if message.typ.method == .allocate {
		r.mu.lock()
		r.allocate_attempts++
		r.mu.unlock()
	}

	// Every request must be authenticated. An unauthenticated one, or one
	// carrying a nonce we have rotated away from, is challenged.
	r.mu.lock()
	current_nonce := r.nonce
	r.mu.unlock()

	username := message.username() or {
		r.challenge(message, stun.code_unauthenticated, current_nonce)
		return
	}
	nonce := message.nonce() or {
		r.challenge(message, stun.code_unauthenticated, current_nonce)
		return
	}
	realm := message.realm() or {
		r.challenge(message, stun.code_unauthenticated, current_nonce)
		return
	}
	if nonce != current_nonce {
		r.challenge(message, stun.code_stale_nonce, current_nonce)
		return
	}

	r.mu.lock()
	r.last_realm = realm
	r.mu.unlock()

	key := stun.long_term_key(username, realm, 'pass') or { return }
	message.check_message_integrity(key) or {
		r.error_response(message, stun.code_wrong_credentials, 'bad credentials', key)
		return
	}

	r.mu.lock()
	refusal := r.refusal
	refusal_reason := r.refusal_reason
	r.mu.unlock()
	if refusal != 0 {
		r.error_response(message, refusal, refusal_reason, key)
		return
	}

	match message.typ.method {
		.allocate { r.answer_allocate(message, key, from) }
		.refresh { r.answer_refresh(message, key) }
		.create_permission { r.answer_create_permission(message, key, from) }
		.channel_bind { r.answer_channel_bind(message, key, from) }
		else {}
	}
}

fn (mut r FakeRelay) answer_allocate(request stun.Message, key []u8, from net.Addr) {
	r.mu.lock()
	// One relayed address per client, so two clients on this relay can be told
	// apart and forwarded between.
	mut relayed := netaddr.SocketAddr{}
	if existing := r.allocations[from.str()] {
		relayed = existing.relayed
	} else {
		relayed = netaddr.SocketAddr.parse('127.0.0.1:${r.next_port}') or {
			r.mu.unlock()
			return
		}
		r.next_port++
		r.allocations[from.str()] = Allocation{
			client:  from
			relayed: relayed
		}
	}
	r.allocated = true
	r.mu.unlock()

	mut response := stun.Message.response(request, .success_response)
	response.add_xor_relayed_address(relayed) or { return }
	mapped := netaddr.SocketAddr.parse('198.51.100.4:33000') or { return }
	response.add_xor_mapped_address(mapped) or { return }
	response.add_lifetime(600)
	r.reply(mut response, key)
}

// forward delivers a relayed payload to whichever allocation owns the target
// address. That makes two clients on this relay able to reach each
// other.
fn (mut r FakeRelay) forward(target netaddr.SocketAddr, data []u8) {
	r.mu.lock()
	mut destination := ?Allocation(none)
	for _, allocation in r.allocations {
		if allocation.relayed.str() == target.str() {
			destination = allocation
			break
		}
	}
	mut sender := netaddr.SocketAddr{}
	if current := r.client {
		if allocation := r.allocations[current.str()] {
			sender = allocation.relayed
		}
	}
	r.mu.unlock()

	allocation := destination or { return }
	if !allocation.permissions[sender.str()] {
		return
	}

	mut channel := u16(0)
	for number, peer in allocation.channels {
		if peer == sender.str() {
			channel = number
			break
		}
	}

	raw := if channel != 0 {
		ChannelData{
			channel: channel
			payload: data
		}.encode() or { return }
	} else {
		mut indication := stun.Message.new(.indication, .data) or { return }
		indication.add_xor_peer_address(sender) or { return }
		indication.add_data(data) or { return }
		indication.encode() or { return }
	}
	r.conn.write_to(allocation.client, raw) or {}
}

fn (mut r FakeRelay) answer_refresh(request stun.Message, key []u8) {
	lifetime := request.lifetime() or { u32(600) }
	mut response := stun.Message.response(request, .success_response)
	response.add_lifetime(lifetime)
	if lifetime == 0 {
		r.mu.lock()
		r.allocated = false
		r.mu.unlock()
	}
	r.reply(mut response, key)
}

fn (mut r FakeRelay) answer_create_permission(request stun.Message, key []u8, from net.Addr) {
	peer := request.xor_peer_address() or { return }
	r.mu.lock()
	r.permissions[peer.str()] = true
	if mut allocation := r.allocations[from.str()] {
		allocation.permissions[peer.str()] = true
		r.allocations[from.str()] = allocation
	}
	r.mu.unlock()
	mut response := stun.Message.response(request, .success_response)
	r.reply(mut response, key)
}

fn (mut r FakeRelay) answer_channel_bind(request stun.Message, key []u8, from net.Addr) {
	peer := request.xor_peer_address() or { return }
	channel := request.channel_number() or { return }
	r.mu.lock()
	r.channels[channel] = peer.str()
	r.permissions[peer.str()] = true
	if mut allocation := r.allocations[from.str()] {
		allocation.channels[channel] = peer.str()
		allocation.permissions[peer.str()] = true
		r.allocations[from.str()] = allocation
	}
	r.mu.unlock()
	mut response := stun.Message.response(request, .success_response)
	r.reply(mut response, key)
}

fn (mut r FakeRelay) challenge(request stun.Message, code int, nonce string) {
	mut response := stun.Message.response(request, .error_response)
	response.add_error_code(code, 'authentication required') or { return }
	response.add_realm(relay_realm) or { return }
	response.add_nonce(nonce) or { return }
	raw := response.encode() or { return }
	r.send(raw) or {}
}

fn (mut r FakeRelay) error_response(request stun.Message, code int, reason string, key []u8) {
	mut response := stun.Message.response(request, .error_response)
	response.add_error_code(code, reason) or { return }
	r.reply(mut response, key)
}

fn (mut r FakeRelay) reply(mut response stun.Message, key []u8) {
	raw := response.encode(integrity_key: key) or { return }
	r.send(raw) or {}
}

// channel_data_header is the channel number and payload length in front of a
// ChannelData payload (RFC 8656 section 12.4).
const channel_data_header = 4

fn is_channel_data(b []u8) bool {
	return b.len >= channel_data_header && b[0] >= 0x40 && b[0] <= 0x7f
}

struct ChannelData {
	channel u16
	payload []u8
}

fn (c ChannelData) encode() ![]u8 {
	if c.channel < 0x4000 || c.channel > 0x7fff {
		return error('channel ${c.channel} is outside the 0x4000-0x7FFF range')
	}
	mut w := codec.Writer.with_capacity(channel_data_header + c.payload.len)
	w.u16(c.channel)
	w.u16(u16(c.payload.len))
	w.bytes(c.payload)
	return w.buf
}

fn decode_channel_data(b []u8) !ChannelData {
	mut r := codec.Reader.new(b)
	channel := r.u16('channel number')!
	length := r.u16('length')!
	payload := r.bytes(int(length), 'payload')!
	return ChannelData{
		channel: channel
		payload: payload
	}
}
