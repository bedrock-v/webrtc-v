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
