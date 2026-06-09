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