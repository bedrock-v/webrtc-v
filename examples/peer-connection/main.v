// The same connection as examples/datachannel, through the PeerConnection API.
//
// Run with: v run examples/peer-connection
//
// Two peers exchange an offer, an answer and their candidates - the four things
// a real deployment would push through its signalling channel - and everything
// below that is handled for them: ICE, DTLS, SCTP, the data channel roles and
// the stream identifiers.
module main

import time
import webrtc
import webrtc.logging