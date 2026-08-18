// The whole WebRTC data channel path, end to end over real sockets.
//
// Run with: v run examples/datachannel
//
// ICE finds a route, DTLS authenticates the peers over it, SCTP runs inside the
// DTLS connection, and a data channel is one SCTP stream pair. Both endpoints
// live in this process; everything they exchange directly - ICE credentials and
// candidates, and the DTLS fingerprints - is what a real deployment sends
// through its signalling channel.
module main

import time
import webrtc.datachannel
import webrtc.dtls
import webrtc.ice
import webrtc.logging
import webrtc.sctp