# Examples

Each directory is a standalone program. Run one with `v run examples/<name>`, or
build them all with `make examples`.

| Example | Network needed | What it shows |
|---|---|---|
| [`sdp-parse`](sdp-parse) | none | Parsing a browser offer and reading the WebRTC attributes out of it |
| [`rtp-roundtrip`](rtp-roundtrip) | none | Building RTP and RTCP, protecting them with SRTP, and what happens to a replayed or tampered packet |
| [`ice-loopback`](ice-loopback) | loopback only | Two ICE agents connecting to each other and exchanging data |
| [`ice-dtls`](ice-dtls) | loopback only | The whole secure path: ICE, then DTLS, then SRTP keyed from the handshake |
| [`datachannel`](datachannel) | loopback only | The whole stack assembled by hand: ICE, DTLS, SCTP and a data channel |
| [`peer-connection`](peer-connection) | loopback only | The same connection through the top-level API: an offer, an answer and a data channel |
| [`stun-discover`](stun-discover) | internet | Asking a STUN server for your public address |

## `sdp-parse`

```sh
v run examples/sdp-parse
```

Parses a representative offer - one audio section and one data channel section,
bundled - and prints the codecs, ICE credentials, DTLS fingerprint, setup role
and SCTP parameters. Finishes by re-serialising it and confirming the output is
byte for byte identical to the input, including the attributes the program never
looked at.
