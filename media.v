module webrtc

import sync
import time
import webrtc.dtls
import webrtc.ice
import webrtc.logging
import webrtc.rtp
import webrtc.rtcp
import webrtc.srtp

// Media over the same socket the handshake used.
//
// WebRTC multiplexes DTLS, RTP and RTCP onto one ICE transport, so something
// has to look at each datagram and decide where it goes. RFC 7983 fixes that by
// the first byte: 20-63 is DTLS, 128-191 is RTP or RTCP, and within that the
// payload type separates the two. MediaTransport does the demultiplexing, hands
// DTLS to the handshake and protects everything else with the keys the
// handshake exported.

// media_queue_depth bounds how many packets may wait to be read. A reader that
// stops reading must not be able to make us buffer without limit, so the
// oldest packet is dropped instead - which is also the right thing for
// real-time media, where a late packet is worth less than a fresh one.
const media_queue_depth = 256