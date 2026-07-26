module dtls

import time
import webrtc.internal.randutil

// The handshake driver.
//
// Both sides are written as an explicit sequence of flights rather than as a
// table-driven state machine. DTLS has six flights and they run in one order;
// spelling them out keeps each side readable against RFC 6347 section 4.2.4,
// and keeps the retransmission - which is the part that actually needs care on
// a lossy transport - visible at each step.

// handshake runs the handshake to completion.
//
// It blocks. On return the connection is either connected or failed, and a
// failed connection is not retryable: the ephemeral keys and the transcript
// belong to the attempt that failed.
pub fn (mut c Conn) handshake() ! {
	if c.state != .new {
		return ConnError{
			reason: .wrong_state
			detail: 'handshake has already been attempted; this connection is ${c.state}'
		}
	}
	c.state = .handshaking
	deadline := time.now().add(c.config.handshake_timeout)

	if c.is_client {
		c.run_client(deadline) or {
			c.state = .failed
			return err
		}
	} else {
		c.run_server(deadline) or {
			c.state = .failed
			return err
		}
	}

	c.state = .connected
	c.log.info('handshake complete as ${c.role()}${c.srtp_note()}')
}

fn (c &Conn) srtp_note() string {
	profile := c.negotiated_srtp_profile or { return '' }
	return ', SRTP profile ${profile}'
}