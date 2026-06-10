// Package turn is a TURN client (RFC 8656): it asks a relay for an address and
// forwards traffic through it.
//
// A relay is what connects two peers that cannot reach each other directly -
// symmetric NAT on both sides, or a network that blocks everything but the
// path to the relay. It costs the relay's bandwidth and adds a hop, so ICE
// tries it last; but when it is needed, nothing else works.
//
// This is the client half only. Running a relay is a different program with
// different concerns (quotas, abuse, accounting) and does not belong in a
// library that dials out.
module turn

import webrtc.internal.codec
import webrtc.netaddr