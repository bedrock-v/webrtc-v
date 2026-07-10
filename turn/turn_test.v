module turn

import net
import sync
import time
import webrtc.netaddr
import webrtc.stun
import webrtc.transport
import webrtc.ice

// Tests for the relay client.
//
// The client is exercised against a relay implemented here rather than against
// a real server: a test that needs the internet is a test that does not run.
// The stand-in speaks the parts of RFC 8656 the client uses - the long-term
// credential challenge, allocation, permissions, channels, and both framings -
// and it is deliberately strict, refusing anything the RFC says it should.

fn test_channel_data_round_trips() {
	framed := ChannelData{
		channel: 0x4001
		payload: [u8(1), 2, 3, 4, 5]
	}
	encoded := framed.encode()!
	assert encoded.len == channel_header_size + 5
	assert is_channel_data(encoded)

	decoded := decode_channel_data(encoded)!
	assert decoded.channel == 0x4001
	assert decoded.payload == [u8(1), 2, 3, 4, 5]
}

fn test_a_channel_number_outside_the_range_is_refused() {
	for channel in [u16(0), 0x3fff, 0x8000, 0xffff] {
		if _ := ChannelData{
			channel: channel
			payload: [u8(1)]
		}.encode()
		{
			assert false, 'channel ${channel} is not a valid channel number'
		}
	}
}

fn test_channel_data_is_told_apart_from_stun() {
	// RFC 7983 demultiplexes on the first byte, so this is what keeps relayed
	// data from being parsed as a STUN message and the other way round.
	message := stun.Message.new(.request, .allocate)!
	mut copy := message
	encoded := copy.encode()!
	assert !is_channel_data(encoded)

	framed := ChannelData{
		channel: channel_min
		payload: [u8(0)]
	}.encode()!
	assert is_channel_data(framed)
	assert !is_channel_data([]u8{})
	assert !is_channel_data([u8(0x40), 0x00])
}

fn test_truncated_channel_data_is_refused() {
	if _ := decode_channel_data([u8(0x40), 0x01]) {
		assert false, 'a two-byte datagram cannot be channel data'
	}
	// A length field that claims more than the datagram carries.
	if _ := decode_channel_data([u8(0x40), 0x01, 0x00, 0x10, 0x01, 0x02]) {
		assert false, 'the length field must be checked against what arrived'
	}
}

fn test_credentials_are_required() {
	if _ := Client.new('127.0.0.1:3478', ClientConfig{}) {
		assert false, 'a relay without credentials is an open relay'
	}
	if _ := Client.new('127.0.0.1:3478', username: 'u') {
		assert false, 'a password is required too'
	}
}

fn test_a_bad_server_address_is_refused() {
	if _ := Client.new('not-an-address', username: 'u', password: 'p') {
		assert false, 'the server address has to parse'
	}
}

fn test_an_allocation_is_made_and_released() {
	mut server := FakeRelay.start()!
	defer {
		server.stop()
	}

	mut client := Client.new(server.address(), username: 'user', password: 'pass')!
	defer {
		client.close()
	}

	relayed := client.allocate()!
	assert relayed.port != 0
	assert client.relayed_address()? == relayed
	// The allocation response also reports what the relay saw us coming from,
	// which is a server-reflexive candidate for free.
	assert client.mapped_address() != none

	// The first request goes out unauthenticated and is challenged, so the
	// exchange must have taken two transactions.
	assert server.allocate_attempts() == 2
	assert server.last_realm() == 'webrtc-v.test'
}

fn test_the_wrong_password_is_rejected() {
	mut server := FakeRelay.start()!
	defer {
		server.stop()
	}

	mut client := Client.new(server.address(),
		username: 'user'
		password: 'wrong'
		rto:      50 * time.millisecond
	)!
	defer {
		client.close()
	}

	if _ := client.allocate() {
		assert false, 'the relay must not allocate for a bad password'
	} else {
		assert err is TurnError
		if err is TurnError {
			assert err.reason == .unauthorized
			assert err.code == stun.code_wrong_credentials
		}
	}
}

fn test_a_stale_nonce_is_retried() {
	mut server := FakeRelay.start()!
	defer {
		server.stop()
	}

	mut client := Client.new(server.address(), username: 'user', password: 'pass')!
	defer {
		client.close()
	}
	client.allocate()!

	// The relay rotates its nonce, as a real one does periodically. The next
	// request must be answered with 438 and then succeed, without the caller
	// seeing anything.
	server.rotate_nonce()
	peer := netaddr.SocketAddr.parse('203.0.113.7:5000')!
	client.create_permission(peer)!
	assert server.has_permission(peer)
}

fn test_data_is_relayed_through_a_send_indication() {
	mut server := FakeRelay.start()!
	defer {
		server.stop()
	}

	mut client := Client.new(server.address(), username: 'user', password: 'pass')!
	defer {
		client.close()
	}
	client.allocate()!

	peer := netaddr.SocketAddr.parse('203.0.113.7:5000')!
	client.create_permission(peer)!
	client.send_to(peer, 'to the peer'.bytes())!

	sent := server.wait_for_relayed(2 * time.second)!
	assert sent.data == 'to the peer'.bytes()
	assert sent.peer.str() == peer.str()

	// And the other direction: the relay wraps what the peer sent in a Data
	// indication.
	server.deliver_from_peer(peer, 'from the peer'.bytes())!
	received := client.recv(2 * time.second)!
	assert received.data == 'from the peer'.bytes()
	assert received.from.str() == peer.str()
}

fn test_a_bound_channel_uses_the_short_framing() {
	mut server := FakeRelay.start()!
	defer {
		server.stop()
	}

	mut client := Client.new(server.address(), username: 'user', password: 'pass')!
	defer {
		client.close()
	}
	client.allocate()!

	peer := netaddr.SocketAddr.parse('203.0.113.9:6000')!
	channel := client.bind_channel(peer)!
	assert channel >= channel_min && channel <= channel_max
	// Binding installs a permission as a side effect.
	assert server.has_permission(peer)

	client.send_to(peer, 'short header'.bytes())!
	sent := server.wait_for_relayed(2 * time.second)!
	assert sent.data == 'short header'.bytes()
	assert sent.channel == channel, 'a bound peer must use channel data, not an indication'

	// The relay answers on the channel, and the client has to attribute it to
	// the right peer from the channel number alone.
	server.deliver_on_channel(channel, 'answer'.bytes())!
	received := client.recv(2 * time.second)!
	assert received.data == 'answer'.bytes()
	assert received.from.str() == peer.str()

	// Binding the same peer again reuses the channel rather than spending a new
	// number on it.
	assert client.bind_channel(peer)! == channel
}

fn test_sending_without_an_allocation_is_refused() {
	mut server := FakeRelay.start()!
	defer {
		server.stop()
	}
	mut client := Client.new(server.address(), username: 'user', password: 'pass')!
	defer {
		client.close()
	}

	peer := netaddr.SocketAddr.parse('203.0.113.7:5000')!
	if _ := client.send_to(peer, 'nowhere'.bytes()) {
		assert false, 'there is no allocation to send through'
	} else {
		assert err is TurnError
		if err is TurnError {
			assert err.reason == .no_allocation
		}
	}
}

fn test_a_silent_relay_times_out() {
	mut server := FakeRelay.start()!
	server.go_silent()
	defer {
		server.stop()
	}

	mut client := Client.new(server.address(),
		username:          'user'
		password:          'pass'
		rto:               20 * time.millisecond
		max_transmissions: 3
	)!
	defer {
		client.close()
	}

	if _ := client.allocate() {
		assert false, 'a relay that never answers cannot produce an allocation'
	} else {
		assert err is TurnError
		if err is TurnError {
			assert err.reason == .timed_out
		}
	}
}

fn test_data_for_an_unbound_channel_is_discarded() {
	// There is no peer address to attribute it to, so it must not be handed to
	// the application under some guess.
	mut server := FakeRelay.start()!
	defer {
		server.stop()
	}
	mut client := Client.new(server.address(), username: 'user', password: 'pass')!
	defer {
		client.close()
	}
	client.allocate()!

	server.deliver_on_channel(0x4123, 'unattributable'.bytes())!
	if _ := client.recv(200 * time.millisecond) {
		assert false, 'data on an unbound channel has no sender and must be dropped'
	}
}

fn test_a_refused_allocation_reports_the_code() {
	mut server := FakeRelay.start()!
	server.refuse_with(stun.code_allocation_quota_reached, 'quota reached')
	defer {
		server.stop()
	}

	mut client := Client.new(server.address(),
		username: 'user'
		password: 'pass'
		rto:      50 * time.millisecond
	)!
	defer {
		client.close()
	}

	if _ := client.allocate() {
		assert false, 'the relay refused'
	} else {
		assert err is TurnError
		if err is TurnError {
			assert err.reason == .refused
			assert err.code == stun.code_allocation_quota_reached
			assert err.msg().contains('486')
		}
	}
}

// -- A relay to test against -------------------------------------------------

struct Relayed {
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

struct FakeRelay {
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
	// allocations is keyed by the client's transport address, which is what
	// makes this relay able to forward between two clients rather than merely
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

fn FakeRelay.start() !&FakeRelay {
	mut conn := net.listen_udp('127.0.0.1:0')!
	mut relay := &FakeRelay{
		conn: conn
	}
	relay.threads << spawn relay.run()
	return relay
}

fn (mut r FakeRelay) address() string {
	bound := transport.local_addr(r.conn) or { panic(err) }
	return bound.str()
}

fn (mut r FakeRelay) stop() {
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

fn (mut r FakeRelay) go_silent() {
	r.mu.lock()
	r.silent = true
	r.mu.unlock()
}

fn (mut r FakeRelay) refuse_with(code int, reason string) {
	r.mu.lock()
	r.refusal = code
	r.refusal_reason = reason
	r.mu.unlock()
}

fn (mut r FakeRelay) rotate_nonce() {
	r.mu.lock()
	r.nonce = 'nonce-two'
	r.mu.unlock()
}

fn (mut r FakeRelay) allocate_attempts() int {
	r.mu.lock()
	defer {
		r.mu.unlock()
	}
	return r.allocate_attempts
}

fn (mut r FakeRelay) last_realm() string {
	r.mu.lock()
	defer {
		r.mu.unlock()
	}
	return r.last_realm
}

fn (mut r FakeRelay) has_permission(peer netaddr.SocketAddr) bool {
	r.mu.lock()
	defer {
		r.mu.unlock()
	}
	return r.permissions[peer.str()] or { false }
}

fn (mut r FakeRelay) wait_for_relayed(timeout time.Duration) !Relayed {
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
fn (mut r FakeRelay) deliver_from_peer(peer netaddr.SocketAddr, data []u8) ! {
	mut indication := stun.Message.new(.indication, .data)!
	indication.add_xor_peer_address(peer)!
	indication.add_data(data)!
	r.send(indication.encode()!)!
}

fn (mut r FakeRelay) deliver_on_channel(channel u16, data []u8) ! {
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
			// A real relay drops what has no permission, which is the whole
			// point of permissions.
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
// address, which is what makes two clients on this relay able to reach each
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
		// No permission, no delivery. This is the rule that stops an allocation
		// from being a service for anyone who learns its address.
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