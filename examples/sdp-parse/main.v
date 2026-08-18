// Parse a browser offer and print what it describes.
//
// Run with: v run examples/sdp-parse
module main

import webrtc.sdp

// A representative offer: one audio section and one data channel section,
// bundled onto a single transport. Written with plain newlines and converted on
// use, because SDP requires CRLF and an escaped literal is unreadable.
const offer = '
v=0
o=- 4611731400430051336 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0 1
a=msid-semantic: WMS stream-id
m=audio 9 UDP/TLS/RTP/SAVPF 111 0 8
c=IN IP4 0.0.0.0
a=ice-ufrag:4ZcD
a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZw
a=ice-options:trickle
a=fingerprint:sha-256 75:74:5A:A6:A4:E5:52:F4:A7:67:4C:01:C7:EE:91:3F:21:3D:A2:E3:53:7B:6F:30:86:F2:30:AA:65:FB:04:24
a=setup:actpass
a=mid:0
a=sendrecv
a=rtcp-mux
a=rtpmap:111 opus/48000/2
a=fmtp:111 minptime=10;useinbandfec=1
a=rtcp-fb:111 transport-cc
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=ssrc:1001 cname:cname-value
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=ice-ufrag:4ZcD
a=ice-pwd:2/1muCWoOi3uLifh0NuRHlZw
a=setup:actpass
a=mid:1
a=sctp-port:5000
a=max-message-size:262144
'.trim_left('\n').replace('\n',
	'\r\n')