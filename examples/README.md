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

## `rtp-roundtrip`

```sh
v run examples/rtp-roundtrip
```

Builds RTP packets with an RFC 8285 header extension, protects them with
AES-GCM SRTP, and unprotects them again. Shows that the header stays readable
while the payload does not, and demonstrates the two ways a packet is rejected:
as a replay, and as a failed authentication.

The keys are made up. In a real connection they come from the DTLS handshake.

## `ice-loopback`

```sh
v run examples/ice-loopback
WEBRTC_LOG_LEVEL=debug v run examples/ice-loopback   # to watch the checks
```

Runs two ICE agents in one process. Everything they exchange - credentials and
candidates - is what a real deployment would send through its signalling
channel; the media path itself is negotiated over real UDP sockets. Prints the
candidates each side gathered, the pair that won, its round-trip time, and the
data that crossed it.

Uses loopback candidates, which are off by default because they can only ever
pair with the same machine.
