// Ask a STUN server what address the internet sees this machine as.
//
// Run with: v run examples/stun-discover [server:port]
//
// This is the discovery half of what ICE does when it gathers a
// server-reflexive candidate. Note that the answer belongs to the socket that
// asked: a NAT mapping is created for a source port, so this address is only
// usable from the socket the client opened, which is why the ICE agent runs the
// same exchange on each of its own sockets rather than calling this.
module main

import os
import time
import webrtc.logging
import webrtc.stunclient

const default_server = 'stun.l.google.com:19302'