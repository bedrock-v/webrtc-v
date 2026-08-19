# Changelog

All notable changes to this project are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the major version is 0, the public API may change in any minor release;
breaking changes are listed under **Changed** with a migration note.

## [Unreleased]

### Added

- **`dtls`** - DTLS 1.2 (RFC 6347) with the DTLS-SRTP profile (RFC 5764).
  Includes the record layer with per-epoch replay detection, handshake
  fragmentation and reassembly, the HelloVerifyRequest cookie exchange,
  retransmission with the RFC 6347 backoff, mutual authentication against the
  certificate fingerprints from signalling, extended master secret (RFC 7627),
  and keying material export for SRTP.
  - Cipher suite: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.
  - Self-signed P-256 certificate generation through a minimal ASN.1 DER
    encoder, verified against OpenSSL.
  - Runs over anything satisfying its `Transport` interface, which an
    `ice.Agent` does as written.
- **`sctp`** - SCTP (RFC 4960) over DTLS: the association handshake with its
  state cookie, DATA and SACK with gap blocks and duplicate reporting, message
  fragmentation and reassembly, ordered and unordered delivery per stream,
  retransmission with RFC 4960 round-trip estimation, fast retransmit,
  slow start and congestion avoidance, flow control through the advertised
  receive window, FORWARD_TSN handling, and graceful shutdown. Checksums use
  CRC-32c, verified against the CRC catalogue check value.
- **`datachannel`** - WebRTC data channels: the DCEP handshake of RFC 8832, the
  payload protocol identifiers of RFC 8831 including the empty-message forms,
  ordered and unordered channels, partial reliability, negotiated channels, and
  the RFC 8832 stream identifier parity that keeps the two ends apart.
- **`examples/ice-dtls`** - the secure media path end to end: ICE connectivity,
  a DTLS handshake over the selected pair, and SRTP keyed from it.
- **`examples/datachannel`** - the whole stack end to end, from ICE through to a
  data channel carrying messages.
- **`webrtc`** - the top-level `PeerConnection`: offer and answer generation and
  application with the JSEP state machine, BUNDLE onto one transport, the DTLS
  role settled from `a=setup` per RFC 5763, trickled or in-description
  candidates, and the transports brought up in order on a background thread.
  - Data channels created before or after the connection is up, and channels the
    peer opens delivered through `accept_data_channel`.
  - Media sections are negotiated and keyed: a demultiplexer sorts DTLS from
    RTP and RTCP per RFC 7983, and `send_rtp`, `recv_rtp`, `send_rtcp` and
    `recv_rtcp` work over SRTP contexts derived from the handshake.
  - `statistics()` reports one consistent snapshot of every transport.
- **`examples/peer-connection`** - a complete offer/answer exchange and a data
  channel, through the top-level API.
- **`internal/aes`** - AES in the encryption direction with the round tables,
  plus CTR and GCM. It replaces `crypto.aes` throughout DTLS and SRTP, which
  were the whole stack's throughput ceiling: measured in a `-prod` build,
  AES-GCM went from 3.0 MB/s to 119 MB/s, and a data channel from 2.0 MB/s to
  6.5 MB/s. Validated against the FIPS-197 vectors, the GCM specification's own
  vectors, an independent bit-at-a-time reference implementation in the tests,
  and differentially against the standard library.
- **`examples/throughput`** and `make bench` - a repeatable measurement of the
  data channel, so a performance claim can be checked rather than believed.
- **`turn`** - a TURN client (RFC 8656) over UDP: allocation with the long-term
  credential challenge, refresh, permissions, channel binding and both framings,
  with the allocation, its permissions and its channels kept alive by a
  maintenance thread. `ice` gathers relayed candidates from any configured
  relay and routes checks and data through the allocation, so the check list
  cannot tell a relayed pair from a direct one. The stack now connects two peers
  that have no path to each other, which is tested end to end against a relay
  implemented in the test suite.
- **`mdns`** - a multicast DNS resolver for the ".local" candidates of RFC 8828,
  which is what a browser signals instead of its private addresses. `ice` parses
  such a candidate instead of refusing it and resolves it on a background
  thread, so a local-network path is not lost. Registering a name for this end's
  own candidates is not implemented.
- **`stun`** - typed accessors for the TURN attributes: LIFETIME,
  REQUESTED-TRANSPORT, DATA, CHANNEL-NUMBER and DONT-FRAGMENT.
- **`ice`** - a gather policy (`all`, `no_host`, `relay_only`), exposed on a peer
  connection as `ice_gather_policy`. Under `no_host` the sockets are still bound
  but no host candidate is signalled, so a peer learns only what a STUN server
  saw. `relay_only` gathers relayed candidates and nothing else, and is refused
  outright when no relay is configured rather than silently falling back to
  disclosing local addresses.
- **`sctp`** - partial reliability on the sending side (RFC 3758). A stream can
  be given a retransmission limit or a deadline; a message that exhausts it is
  abandoned whole, and the peer is told to skip it with FORWARD_TSN. Nothing is
  abandoned unless the peer advertised support, and `Config.partial_reliability`
  turns the advertisement off. `datachannel` wires `max_retransmits` and
  `max_packet_lifetime` through to it in both directions, so an unreliable
  channel is now actually unreliable rather than merely labelled so.

### Fixed

- **Performance measurement**: the documented "about 50 KB/s on loopback,
  limited by the association loop's 20 ms tick" was wrong in both the number and
  the cause. It was measured in an unoptimised build, and the real limit was the
  standard library's AES. V's default build is not optimised, and this stack is
  CPU-bound on the cipher, so anything measured without `-prod` reports roughly a
  third of the real figure.

- **`sctp`**: the acknowledgement point started at zero rather than one below
  the initial transmission sequence number. Since that number is random, roughly
  half of all associations discarded every acknowledgement the peer sent, never
  opened the congestion window, and stalled permanently on any transfer larger
  than it.
- **`sctp`**: the per-chunk payload limit did not account for the four-byte chunk
  padding, so packets were one byte over the transport's maximum whenever that
  maximum was not itself a multiple of four - which is the case over DTLS.
- **`ice`**: a nominated candidate pair lost a priority comparison against an
  already-selected pair, so a controlled agent could ignore the nomination and
  keep using a path the peer had stopped using.
- **`ice`**: sorting an empty check list faulted inside V's stable sort, which
  an agent has whenever it gathers before the peer's candidates arrive.
- **`sctp`**: FORWARD_TSN discarded data the receiver had already accepted. The
  sender's acknowledgement point may legitimately cover transmission sequence
  numbers reported in a gap block, so skipping ahead has to deliver what
  arrived and skip only what did not; it deleted the lot, losing messages the
  sender believed were delivered.
- **`datachannel`**: `Manager.accept` returned a nil channel when the manager was
  closed while a caller was waiting, because a receive on a closed V channel
  completes with the zero value. Callers dereferenced it and crashed on
  shutdown.

## [0.1.0] - 2026-08-20

First release. The protocol layers below are implemented and tested; DTLS, SCTP,
data channels and the peer connection API are not yet written, so this cannot
open a browser-compatible connection.
