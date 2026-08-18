// Connect two ICE agents to each other inside one process.
//
// Run with: v run examples/ice-loopback
//
// The two agents are what a real deployment would have on two different
// machines. Everything they exchange here through direct calls - credentials
// and candidates - is exactly what a real deployment sends through its
// signalling channel, and nothing else passes between them: the media path is
// negotiated by ICE over real UDP sockets.
module main

import time
import webrtc.ice
import webrtc.logging