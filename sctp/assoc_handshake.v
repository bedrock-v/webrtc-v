module sctp

import time
import webrtc.internal.randutil

// Association establishment and teardown (RFC 4960 section 5).
//
// The four-way handshake exists because SCTP runs over an unauthenticated
// datagram transport in the general case: the server commits no memory until
// the client echoes a cookie proving it can receive at its claimed address.
// Over DTLS the peer is already authenticated, so the exchange is mostly
// ceremony here - but a peer that expects it will not proceed without it.

// connect establishes the association and blocks until it is usable.
pub fn (mut a Association) connect(timeout time.Duration) ! {
	a.mu.lock()
	if a.state != .closed {
		state := a.state
		a.mu.unlock()
		return AssociationError{
			reason: .wrong_state
			detail: 'the association is already ${state}'
		}
	}
	is_client := a.is_client
	a.mu.unlock()

	a.start()

	if is_client {
		a.send_init()!
	}

	deadline := time.now().add(timeout)
	for time.now() < deadline {
		state := a.state()
		match state {
			.established {
				return
			}
			.aborted {
				a.mu.lock()
				reason := a.abort_reason
				a.mu.unlock()
				return AssociationError{
					reason: .aborted
					detail: if reason != '' { reason } else { 'the association was aborted' }
				}
			}
			.closed {
				a.mu.lock()
				torn_down := a.torn_down
				reason := a.abort_reason
				a.mu.unlock()
				if torn_down {
					return AssociationError{
						reason: .closed
						detail: if reason != '' {
							reason
						} else {
							'the association closed while connecting'
						}
					}
				}
			}
			else {}
		}
		time.sleep(5 * time.millisecond)
	}
	return AssociationError{
		reason: .timed_out
		detail: 'the association did not establish within ${timeout.milliseconds()}ms'
	}
}