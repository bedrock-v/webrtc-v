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

## `ice-dtls`

```sh
v run examples/ice-dtls
WEBRTC_LOG_LEVEL=debug v run examples/ice-dtls   # to watch both layers
```

The complete secure path, end to end in one process. Two ICE agents connect over
real UDP; a DTLS handshake runs over the pair ICE selected, with each side
checking the other's certificate against the fingerprint that was "signalled";
and the handshake exports the keying material that SRTP then uses to protect an
RTP packet in both directions.

Prints the timings for each stage, and finishes by showing that a tampered
packet is rejected.

## `datachannel`

```sh
v run examples/datachannel
WEBRTC_LOG_LEVEL=debug v run examples/datachannel   # to watch every layer
```

The complete WebRTC data channel path in one process: ICE finds a route, DTLS
authenticates the peers over it, SCTP runs inside the DTLS connection, and a data
channel is one SCTP stream pair. Prints the time each layer took, then exchanges
messages, checks that ordering held across ten of them, transfers 60 KB through
SCTP's fragmentation, and opens a second unordered channel.

## `stun-discover`

```sh
v run examples/stun-discover
v run examples/stun-discover stun.cloudflare.com:3478
```

Sends one Binding request and prints the reflexive address the server saw. Needs
outbound UDP to the server.

The address belongs to the socket that asked: a NAT mapping is created for a
source port, so this answer is only usable from that socket. That is why the ICE
agent runs the same exchange on each of its own sockets rather than calling this.
