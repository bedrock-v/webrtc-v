// Parse a browser offer and print what it describes.
//
// Run with: v run examples/sdp-parse
module main

import webrtc.sdp

// A representative offer: one audio section and one data channel section,
// bundled onto a single transport. Written with plain newlines and converted on
// use, because SDP requires CRLF and an escaped literal is unreadable.
const offer = '