# webrtc-v

A pure [V](https://vlang.io) implementation of the WebRTC protocol stack.

No CGO-style bindings to libwebrtc, no C dependencies beyond libc, no build
system to fight. `v install` and import what you need.

> **Status: alpha.** The protocol layers listed as complete below are
> implemented, tested against the RFC test vectors where they exist, and
> exercised over real sockets. Two endpoints exchange an SDP offer and answer,
> find each other with ICE, complete a mutually authenticated DTLS handshake over
> that path, run an SCTP association inside it and exchange data channel
> messages, directly or through a TURN relay. What is missing is media: SRTP is
> keyed and RTP can be sent and received, but there is no track layer above it.
> See [Status](#status) for exactly what works today. The public API may still
> change before 1.0.

## Why

WebRTC outside the browser usually means embedding libwebrtc: a multi-hundred
megabyte C++ tree with its own build system, or a binding to it that inherits
every one of its portability problems. Projects like [Pion](https://pion.ly) and
[webrtc-rs](https://webrtc.rs) showed that a native implementation in a memory-
safe language is both possible and considerably easier to work with. This is
that idea in V.

The design goals, in the order they are traded off:

1. **Correctness against the RFCs.** Every packet format is implemented from the
   specification, with the section number in the comment where the rule is not
   obvious. Where the RFC publishes test vectors, they are in the test suite.
2. **Safety against hostile input.** Everything arriving from the network is
   decoded through one bounds-checked reader. A malformed packet is an error, not
   a panic, and never a read past the end of a buffer.
3. **A layered API.** Each protocol is a module that does one thing. The codecs
   have no I/O at all - you can parse STUN, RTP or SDP without linking a socket -
   and the networked modules are built on top of them.
4. **Being readable.** This is also meant to be a way to learn how WebRTC
   actually works. Comments explain *why*, and point at the specification.

## Status

| Module        | Specification                       | State |
|---------------|-------------------------------------|-------|
| `netaddr`     | IP and socket address values        | ✅ Complete |
| `logging`     | leveled logging                     | ✅ Complete |
| `transport`   | socket ↔ address bridging           | ✅ Complete |
| `stun`        | RFC 8489, RFC 5389                  | ✅ Complete, passes the RFC 5769 vectors |
| `stunclient`  | STUN over UDP with retransmission   | ✅ Complete |
| `turn`        | RFC 8656 client                     | ✅ Complete for UDP |
| `mdns`        | RFC 8828 candidate resolution       | ✅ Resolver only |
| `sdp`         | RFC 8866 + the WebRTC attributes    | ✅ Complete |
| `rtp`         | RFC 3550, RFC 8285                  | ✅ Complete |
| `rtcp`        | RFC 3550, 4585, 5104, REMB, TWCC    | ✅ Complete |
| `srtp`        | RFC 3711, RFC 7714                  | ✅ Complete, passes the RFC 3711 KDF vectors |
| `ice`         | RFC 8445, RFC 8839, RFC 7675        | ✅ Complete for UDP |
| `dtls`        | DTLS 1.2, RFC 5764                  | ✅ Complete for ECDHE-ECDSA-AES128-GCM |
| `sctp`        | RFC 4960 over DTLS                  | ✅ Complete |
| `datachannel` | RFC 8831, RFC 8832                  | ✅ Complete |
| `webrtc`      | RTCPeerConnection, JSEP offer/answer | ✅ Complete for data channels |

What you can build today: a peer-to-peer connection from an offer and an answer.
`webrtc.PeerConnection` does the JSEP part - it builds and reads the SDP, works
out which end is the DTLS client, brings ICE, DTLS and SCTP up in order and
hands you data channels.
[`examples/peer-connection`](examples/peer-connection) is the whole thing in
about forty lines.

Every layer underneath is a module you can use on its own, which is what
[`examples/datachannel`](examples/datachannel) shows: the same connection
assembled by hand, transport by transport.

Relays work: `turn` is an RFC 8656 client, and ICE gathers relayed candidates
from any `turn:` server in the configuration, so a connection is made even when
neither peer can reach the other directly.

What is not there yet: media. RTP, RTCP and SRTP are complete and a negotiated
audio or video section gets keyed SRTP contexts and `send_rtp`/`recv_rtp`, but
there is no track abstraction, no sender or receiver, and no congestion control.

Candidates naming a `.local` host are resolved through multicast DNS, so a
browser's privacy-preserving candidates still produce a local-network path.
Registering such a name for this end's own candidates is not implemented, so
this end's offers carry addresses.

**Platforms.** Linux, macOS and the BSDs are supported and tested. Windows
compiles and works, but interface enumeration falls back to finding one address
per family rather than all of them; see the note in
[`ice/interfaces_windows.c.v`](ice/interfaces_windows.c.v).

## Install

```sh
v install --git https://github.com/bedrock-v/webrtc-v
```

Or, for development, clone the repository and link it into V's module path:

```sh
git clone https://github.com/bedrock-v/webrtc-v
ln -s "$PWD/webrtc-v" ~/.vmodules/webrtc
```

Requires V 0.5.2 or newer.

## Usage
