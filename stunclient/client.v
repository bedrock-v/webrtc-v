// Package stunclient performs STUN transactions over UDP.
//
// It is separate from the stun package because that one is a pure codec with no
// I/O: an application that only needs to parse or build STUN messages should not
// link a socket implementation. This package adds the socket, the timers and the
// retransmission schedule.
module stunclient

import net
import time
import webrtc.logging
import webrtc.netaddr
import webrtc.stun

// max_datagram is the largest datagram the client will read. STUN messages are
// far smaller; the ceiling exists so a hostile server cannot make the client
// allocate an arbitrary buffer.
const max_datagram = 1500

// ClientConfig tunes the retransmission behaviour described in RFC 8489
// section 6.2.1.
//
// The defaults follow the RFC: a 500 ms initial timeout doubling on each retry,
// seven transmissions in total. That is deliberately patient - it is meant for
// a standalone binding lookup. An ICE agent does not use this schedule; it
// paces its own checks and treats each one as a single transmission.
@[params]
pub struct ClientConfig {
pub:
	rto               time.Duration = 500 * time.millisecond
	max_transmissions int           = 7
	// software, when set, is advertised in a SOFTWARE attribute. It is empty by
	// default because naming the implementation and version to every server on
	// the path is a needless disclosure.
	software string
	logger   logging.Logger = logging.nop()
}

// TimeoutError is returned when no valid response arrived within the
// retransmission schedule.
pub struct TimeoutError {
pub:
	transmissions int
	elapsed       time.Duration
}

pub fn (e TimeoutError) msg() string {
	return 'stun: no response after ${e.transmissions} transmissions over ${e.elapsed.milliseconds()}ms'
}

pub fn (e TimeoutError) code() int {
	return 500
}

// Client performs STUN transactions over a connected UDP socket.
//
// One client owns one socket. That matters for ICE: the mapping a NAT creates
// is per source port, so a server-reflexive candidate is only valid for the
// socket that discovered it. Callers that need a candidate for an existing
// socket should drive transactions on that socket themselves rather than
// letting this type open its own.
pub struct Client {
mut:
	conn   &net.UdpConn
	config ClientConfig
	closed bool
pub:
	server string
}

// Client.dial opens a socket to a STUN server given as "host:port".
pub fn Client.dial(server string, config ClientConfig) !&Client {
	if config.max_transmissions < 1 {
		return error('stun: max_transmissions must be at least 1')
	}
	if config.rto <= 0 {
		return error('stun: rto must be positive')
	}
	conn := net.dial_udp(server)!
	return &Client{
		conn:   conn
		config: config
		server: server
	}
}

// close releases the socket. It is safe to call more than once.
pub fn (mut c Client) close() {
	if c.closed {
		return
	}
	c.closed = true
	c.conn.close() or {}
}

// binding performs a Binding request and returns the reflexive transport
// address the server observed.
pub fn (mut c Client) binding() !netaddr.SocketAddr {
	mut req := stun.Message.new(.request, .binding)!
	if c.config.software != '' {
		req.add_software(c.config.software)!
	}
	// FINGERPRINT is not required for a plain Binding request, but it makes the
	// response easy to tell apart from anything else that might arrive on the
	// socket, and costs four bytes.
	resp := c.transact(mut req, fingerprint: true)!

	if resp.typ.class == .error_response {
		return resp.error_code()!
	}
	if resp.typ.class != .success_response {
		return error('stun: expected a success response, got a ${resp.typ.class}')
	}
	return resp.reflexive_address()!
}

// transact sends a request and returns the matching response, retransmitting on
// the configured schedule until one arrives.
pub fn (mut c Client) transact(mut req stun.Message, opts stun.EncodeOptions) !stun.Message {
	if c.closed {
		return error('stun: client is closed')
	}
	raw := req.encode(opts)!
	started := time.now()
	mut rto := c.config.rto

	for attempt in 0 .. c.config.max_transmissions {
		c.conn.write(raw)!
		c.config.logger.debug('sent ${req.typ} to ${c.server}, attempt ${attempt + 1}/${c.config.max_transmissions}')

		deadline := time.now().add(rto)
		for {
			remaining := deadline - time.now()
			if remaining <= 0 {
				break
			}
			c.conn.set_read_timeout(remaining)
			mut buf := []u8{len: max_datagram}
			n, _ := c.conn.read(mut buf) or { break }

			resp := stun.Message.decode(buf[..n]) or {
				// Anything that is not a STUN message on this socket is noise
				// or an attack; keep waiting for the real response.
				c.config.logger.debug('discarded ${n} bytes that did not decode as STUN: ${err.msg()}')
				continue
			}
			if resp.transaction_id != req.transaction_id {
				// An off-path attacker would have to guess 96 random bits to
				// get past this.
				c.config.logger.debug('discarded a response with a mismatched transaction id')
				continue
			}
			if resp.typ.method != req.typ.method {
				c.config.logger.debug('discarded a ${resp.typ.method} response to a ${req.typ.method} request')
				continue
			}
			if resp.has(stun.attr_fingerprint) {
				resp.check_fingerprint() or {
					c.config.logger.debug('discarded a response with a bad FINGERPRINT')
					continue
				}
			}
			return resp
		}

		// RFC 8489 section 6.2.1: double the timeout after each retransmission.
		rto = rto * 2
	}

	return TimeoutError{
		transmissions: c.config.max_transmissions
		elapsed:       time.now() - started
	}
}