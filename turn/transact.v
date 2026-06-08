module turn

import encoding.hex
import time
import webrtc.netaddr
import webrtc.stun
import webrtc.transport

// Transactions, authentication, and the reader that feeds both.

// transact_authenticated runs a request through the long-term credential
// mechanism of RFC 8489 section 9.2.
//
// The exchange is: send without credentials, get 401 with the realm and a
// nonce, derive the key, send again with MESSAGE-INTEGRITY. Once the realm and
// nonce are known they are reused, so only the first request costs the extra
// round trip. A 438 means the nonce has gone stale - the server rotates them -
// and is answered by retrying with the new one, which is a normal part of a
// long-lived allocation rather than an error.
fn (mut c Client) transact_authenticated(mut request stun.Message) !stun.Message {
	c.mu.lock()
	realm := c.realm
	nonce := c.nonce
	key := c.key.clone()
	c.mu.unlock()

	mut response := stun.Message{}
	if realm != '' && nonce != '' && key.len > 0 {
		c.attach_credentials(mut request, realm, nonce)!
		response = c.transact(mut request, integrity_key: key)!
	} else {
		response = c.transact(mut request, stun.EncodeOptions{})!
	}

	if response.typ.class != .error_response {
		return response
	}

	code := response.error_code() or {
		return TurnError{
			reason: .bad_message
			detail: 'an error response with no ERROR-CODE'
		}
	}
	if code.code != stun.code_unauthenticated && code.code != stun.code_stale_nonce {
		return c.server_error(code)
	}

	// Learn the realm and nonce, derive the key, and try once more. Only once:
	// a server that answers the authenticated request with another challenge is
	// either misconfigured or trying to make us loop.
	new_realm := response.realm() or {
		if realm != '' {
			realm
		} else {
			return TurnError{
				reason: .unauthorized
				detail: 'the server asked for credentials without naming a realm'
				code:   code.code
			}
		}
	}
	new_nonce := response.nonce() or {
		return TurnError{
			reason: .unauthorized
			detail: 'the server asked for credentials without a nonce'
			code:   code.code
		}
	}
	new_key := stun.long_term_key(c.config.username, new_realm, c.config.password) or {
		return TurnError{
			reason: .unauthorized
			detail: err.msg()
		}
	}

	c.mu.lock()
	c.realm = new_realm
	c.nonce = new_nonce
	c.key = new_key.clone()
	c.mu.unlock()

	// A retry is a new transaction: reusing the transaction id would let the
	// server treat it as a retransmission of the unauthenticated one.
	mut retry := stun.Message.new(request.typ.class, request.typ.method) or {
		return TurnError{
			reason: .bad_message
			detail: err.msg()
		}
	}
	for attribute in request.attributes {
		if attribute.typ == stun.attr_username || attribute.typ == stun.attr_realm
			|| attribute.typ == stun.attr_nonce {
			continue
		}
		if attribute.typ == stun.attr_message_integrity
			|| attribute.typ == stun.attr_message_integrity_sha256
			|| attribute.typ == stun.attr_fingerprint {
			// The first attempt's encode left these on the message. They cover
			// the bytes of that attempt and are recomputed for this one; copying
			// them across would also be rejected by the encoder, which insists
			// they are requested rather than supplied.
			continue
		}
		if attribute.typ == stun.attr_xor_peer_address {
			// Skipped here and re-added below: the address was XOR-ed with the
			// old transaction id, and copying the bytes would encode a
			// different address under the new one.
			continue
		}
		retry.add(attribute.typ, attribute.value)
	}
	if peer := request.xor_peer_address() {
		retry.add_xor_peer_address(peer) or {
			return TurnError{
				reason: .bad_message
				detail: err.msg()
			}
		}
	}
	c.attach_credentials(mut retry, new_realm, new_nonce)!

	final := c.transact(mut retry, integrity_key: new_key)!
	if final.typ.class == .error_response {
		final_code := final.error_code() or {
			return TurnError{
				reason: .bad_message
				detail: 'an error response with no ERROR-CODE'
			}
		}
		return c.server_error(final_code)
	}

	// The response is authenticated with the same key, which is what stops an
	// off-path attacker from answering on the server's behalf.
	final.check_message_integrity(new_key) or {
		return TurnError{
			reason: .unauthorized
			detail: 'the response did not authenticate: ${err.msg()}'
		}
	}
	return final
}

// server_error turns a STUN error code into a typed failure, separating the
// ones worth retrying from the ones that never will be.
fn (c &Client) server_error(code stun.ErrorCode) TurnError {
	reason := match code.code {
		stun.code_unauthenticated, stun.code_wrong_credentials, stun.code_stale_nonce {
			TurnErrorReason.unauthorized
		}
		stun.code_unsupported_transport_protocol, stun.code_address_family_not_supported {
			TurnErrorReason.unsupported
		}
		else {
			TurnErrorReason.refused
		}
	}
	return TurnError{
		reason: reason
		detail: if code.reason != '' { code.reason } else { 'the server refused the request' }
		code:   code.code
	}
}

fn (mut c Client) attach_credentials(mut message stun.Message, realm string, nonce string) ! {
	message.add_username(c.config.username) or {
		return TurnError{
			reason: .bad_message
			detail: err.msg()
		}
	}
	message.add_realm(realm) or { return TurnError{
		reason: .bad_message
		detail: err.msg()
	} }
	message.add_nonce(nonce) or { return TurnError{
		reason: .bad_message
		detail: err.msg()
	} }
}

// transact sends a request and waits for its response, retransmitting on the
// RFC 8489 schedule.
fn (mut c Client) transact(mut request stun.Message, opts stun.EncodeOptions) !stun.Message {
	if c.is_closed() {
		return TurnError{
			reason: .closed
			detail: 'the client is closed'
		}
	}
	raw := request.encode(opts) or {
		return TurnError{
			reason: .bad_message
			detail: err.msg()
		}
	}

	key := hex.encode(request.transaction_id[..])
	replies := chan stun.Message{cap: 1}
	c.mu.lock()
	c.pending[key] = replies
	c.mu.unlock()
	defer {
		c.mu.lock()
		c.pending.delete(key)
		c.mu.unlock()
	}

	mut rto := c.config.rto
	for attempt in 0 .. c.config.max_transmissions {
		c.write(raw)!
		select {
			response := <-replies {
				return response
			}
			rto {
				c.log.debug('${request.typ.method} attempt ${attempt + 1} timed out, retrying in ${(rto * 2).milliseconds()}ms')
			}
		}
		// RFC 8489 section 6.2.1: double the timeout after each retransmission.
		rto = rto * 2
	}

	return TurnError{
		reason: .timed_out
		detail: 'the relay did not answer a ${request.typ.method} after ${c.config.max_transmissions} attempts'
	}
}