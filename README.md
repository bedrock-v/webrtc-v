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
