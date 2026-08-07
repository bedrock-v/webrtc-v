module datachannel

import sync
import time
import webrtc.logging
import webrtc.sctp

// The data channel layer over an SCTP association.
//
// A Manager owns the association and routes what arrives on it: DCEP messages
// change channel state, and everything else is application data for the channel
// whose stream it came in on. One background thread does the routing, which is
// the same arrangement the layers below use and for the same reason - the
// ordering rules live in one place.

// max_channels bounds how many channels one association may carry. Each one is
// state we hold on behalf of a peer that can open them unilaterally.
pub const max_channels = 512