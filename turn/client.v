module turn

import net
import sync
import time
import webrtc.logging
import webrtc.netaddr
import webrtc.stun
import webrtc.transport

// The relay client.
//
// One socket to the relay carries everything: the transactions that set the
// allocation up, and the relayed traffic itself. A reader thread owns the
// socket and sorts what arrives - a response goes to whoever is waiting for
// that transaction, relayed data goes to the application - which is the same
// arrangement the ICE agent uses, for the same reason: the ordering rules end
// up in one place.

// max_datagram is the largest datagram read from the relay. A relayed payload
// is bounded by the DATA attribute limit, and the framing adds a little.
const max_datagram = 9216

// default_lifetime is the allocation lifetime to ask for. RFC 8656 says a
// server may return less, and the refresh schedule follows what it returns
// rather than what was asked.
pub const default_lifetime = u32(600)

// Packet is one datagram relayed from a peer.
pub struct Packet {
pub:
	from netaddr.SocketAddr
	data []u8
}

@[params]
pub struct ClientConfig {
pub:
	// username and password are the long-term credentials. A TURN server that
	// hands out allocations without them is an open relay, so they are required.
	username string
	password string
	// realm, when set, is used before the server has said which realm it wants.
	// Leaving it empty is normal: the first request is answered with a 401 that
	// names the realm, and the credentials are then derived for it.
	realm string
	// lifetime is the allocation lifetime to request, in seconds.
	lifetime u32 = default_lifetime
	// rto and max_transmissions are the retransmission schedule for a
	// transaction, matching RFC 8489 section 6.2.1.
	rto               time.Duration = 500 * time.millisecond
	max_transmissions int           = 7
	// software, when set, is advertised. Empty by default: naming the
	// implementation to every relay is a needless disclosure.
	software string
	logger   logging.Logger = logging.nop()
}

// Client is a TURN allocation on one relay.
pub struct Client {
mut:
	conn &net.UdpConn
	// destination is the relay's address in the form sendto wants. The socket
	// is not connected, so that a datagram from anywhere else is still received
	// and can be discarded here rather than by the kernel.
	destination net.Addr
	config      ClientConfig
	log         logging.Logger
	mu          &sync.Mutex = sync.new_mutex()

	// realm, nonce and key are the long-term credential state. The key is
	// derived once per realm; the nonce changes whenever the server says so.
	realm string
	nonce string
	key   []u8

	relayed ?netaddr.SocketAddr
	mapped  ?netaddr.SocketAddr
	// lifetime is what the server granted, and refresh_at is when to renew. An
	// allocation that is not refreshed is silently deleted, and the first sign
	// of it is traffic disappearing.
	lifetime   u32
	refresh_at time.Time

	// permissions and bindings are per peer address. A permission lets a peer's
	// traffic through; a channel makes the framing cheap.
	permissions  map[string]time.Time
	bindings     map[string]Binding
	next_channel u16 = channel_min

	// pending routes a response to whoever is waiting for that transaction.
	pending map[string]chan stun.Message
	inbound chan Packet = chan Packet{cap: 256}

	closed  bool
	threads []thread
pub:
	server netaddr.SocketAddr
}

// Client.new opens a socket to the relay. Nothing is allocated until allocate
// is called.
pub fn Client.new(server string, config ClientConfig) !&Client {
	if config.username == '' || config.password == '' {
		// A relay that allocates without credentials is an open relay, and the
		// RFC requires the long-term mechanism for exactly that reason.
		return TurnError{
			reason: .unauthorized
			detail: 'a TURN server needs a username and a password'
		}
	}
	address := netaddr.SocketAddr.parse(server) or {
		return TurnError{
			reason: .transport
			detail: 'bad TURN server address "${server}": ${err.msg()}'
		}
	}

	// Binding to the unspecified address of the server's family, so a v6 relay
	// is reached over v6.
	bind_target := if address.ip.family == .ipv6 { '[::]:0' } else { '0.0.0.0:0' }
	mut conn := net.listen_udp(bind_target) or {
		return TurnError{
			reason: .transport
			detail: 'binding a local socket: ${err.msg()}'
		}
	}
	destination := transport.socket_addr_to_net(address) or {
		conn.close() or {}
		return TurnError{
			reason: .transport
			detail: err.msg()
		}
	}

	mut client := &Client{
		conn:        conn
		destination: destination
		config:      config
		log:         config.logger.with_scope('turn')
		realm:       config.realm
		server:      address
	}
	client.threads << spawn client.read_loop()
	return client
}

// relayed_address is the address the relay allocated, which is what a peer
// sends to. It is none until allocate succeeds.
pub fn (mut c Client) relayed_address() ?netaddr.SocketAddr {
	c.mu.lock()
	defer {
		c.mu.unlock()
	}
	return c.relayed
}

// mapped_address is what the relay saw this client coming from, which is a
// server-reflexive candidate obtained for free by allocating.
pub fn (mut c Client) mapped_address() ?netaddr.SocketAddr {
	c.mu.lock()
	defer {
		c.mu.unlock()
	}
	return c.mapped
}

// allocate asks the relay for an address.
//
// The first request goes out without credentials on purpose. That is not an
// optimism about open relays: RFC 8489 section 9.2 has the server answer with
// the realm and a nonce, and the credentials cannot be computed until it does.
pub fn (mut c Client) allocate() !netaddr.SocketAddr {
	if c.is_closed() {
		return TurnError{
			reason: .closed
			detail: 'the client is closed'
		}
	}

	mut request := stun.Message.new(.request, .allocate) or {
		return TurnError{
			reason: .bad_message
			detail: err.msg()
		}
	}
	request.add_requested_transport(stun.transport_udp)
	request.add_lifetime(c.config.lifetime)
	if c.config.software != '' {
		request.add_software(c.config.software) or {}
	}

	response := c.transact_authenticated(mut request)!

	relayed := response.xor_relayed_address() or {
		return TurnError{
			reason: .bad_message
			detail: 'the allocation response carries no relayed address'
		}
	}
	granted := response.lifetime() or { c.config.lifetime }

	c.mu.lock()
	c.relayed = relayed
	if mapped := response.xor_mapped_address() {
		c.mapped = mapped
	}
	c.lifetime = granted
	c.refresh_at = refresh_time(granted)
	c.mu.unlock()

	c.log.info('allocated ${relayed} on ${c.server}, lifetime ${granted}s')
	c.threads << spawn c.maintain()
	return relayed
}

// refresh renews the allocation. A lifetime of zero deletes it.
pub fn (mut c Client) refresh(lifetime u32) ! {
	mut request := stun.Message.new(.request, .refresh) or {
		return TurnError{
			reason: .bad_message
			detail: err.msg()
		}
	}
	request.add_lifetime(lifetime)
	response := c.transact_authenticated(mut request)!

	if lifetime == 0 {
		c.mu.lock()
		c.relayed = none
		c.mu.unlock()
		return
	}
	granted := response.lifetime() or { lifetime }
	c.mu.lock()
	c.lifetime = granted
	c.refresh_at = refresh_time(granted)
	c.mu.unlock()
	c.log.debug('allocation refreshed for ${granted}s')
}

// create_permission lets a peer's traffic reach the allocation.
//
// Without it the relay drops what the peer sends, which is what stops an
// allocation from being a service for anyone who finds its address. A
// permission lasts five minutes and is refreshed by sending again.
pub fn (mut c Client) create_permission(peer netaddr.SocketAddr) ! {
	mut request := stun.Message.new(.request, .create_permission) or {
		return TurnError{
			reason: .bad_message
			detail: err.msg()
		}
	}
	request.add_xor_peer_address(peer) or {
		return TurnError{
			reason: .bad_message
			detail: err.msg()
		}
	}
	c.transact_authenticated(mut request)!

	c.mu.lock()
	c.permissions[peer.str()] = time.now().add(permission_lifetime)
	c.mu.unlock()
	c.log.debug('permission installed for ${peer}')
}

// bind_channel binds a peer to a channel number, so its traffic carries a
// four-byte header instead of a thirty-six byte one.
//
// A channel binding also installs a permission, so a caller that binds does not
// need to create one separately.
pub fn (mut c Client) bind_channel(peer netaddr.SocketAddr) !u16 {
	key := peer.str()
	c.mu.lock()
	if existing := c.bindings[key] {
		if existing.confirmed && time.now().unix() < existing.refresh_at {
			c.mu.unlock()
			return existing.channel
		}
	}
	channel := c.allocate_channel(key) or {
		c.mu.unlock()
		return TurnError{
			reason: .refused
			detail: 'no channel number is available'
		}
	}
	c.bindings[key] = Binding{
		peer:    peer
		channel: channel
	}
	c.mu.unlock()

	mut request := stun.Message.new(.request, .channel_bind) or {
		return TurnError{
			reason: .bad_message
			detail: err.msg()
		}
	}
	request.add_channel_number(channel)
	request.add_xor_peer_address(peer) or {
		return TurnError{
			reason: .bad_message
			detail: err.msg()
		}
	}
	c.transact_authenticated(mut request)!

	c.mu.lock()
	c.bindings[key] = Binding{
		peer:       peer
		channel:    channel
		confirmed:  true
		refresh_at: time.now().add(channel_refresh_interval).unix()
	}
	// A channel binding installs a permission as a side effect, so recording it
	// keeps the maintenance loop from installing a redundant one.
	c.permissions[key] = time.now().add(permission_lifetime)
	c.mu.unlock()
	c.log.debug('bound ${peer} to channel ${channel}')
	return channel
}