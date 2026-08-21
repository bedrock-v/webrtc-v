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

### A peer connection with a data channel

This is the whole API for the common case. Everything the two peers have to
exchange - the offer, the answer and the candidates - goes through whatever
signalling you already have; nothing else needs to.

```v
import time
import webrtc

fn main() {
	mut pc := webrtc.PeerConnection.new(
		ice_servers: [webrtc.IceServer{
			urls: ['stun:stun.l.google.com:19302']
		}]
	)!
	defer { pc.close() }

	mut chat := pc.create_data_channel('chat')!

	offer := pc.create_offer()!
	pc.set_local_description(offer)!
	// Send offer.sdp and pc.local_candidates() to the peer, and apply what it
	// sends back:
	//   pc.set_remote_description(webrtc.SessionDescription{ typ: .answer, sdp: answer })!
	//   pc.add_ice_candidate(line)!

	pc.wait_connected(30 * time.second)!
	chat.send_text('hello')!

	message := chat.recv(5 * time.second)!
	println(message.text())
}
```

The answering side is the same, in the other order: `set_remote_description`
with the offer, then `create_answer`, `set_local_description`, and
`accept_data_channel` to receive the channels the caller opened.

[`examples/peer-connection`](examples/peer-connection) runs both ends in one
process, so it is a complete, working exchange to read.

### Connect through a relay

When neither peer can reach the other - symmetric NAT on both sides, or a
network that blocks everything but the path out - a TURN server forwards for
them. Add it to the configuration and ICE does the rest: it allocates, gathers
the relayed address as a candidate, and installs the permissions the relay needs
before a check can get through.

```v
mut pc := webrtc.PeerConnection.new(
	ice_servers: [
		webrtc.IceServer{
			urls: ['stun:stun.example:3478']
		},
		webrtc.IceServer{
			urls:       ['turn:relay.example:3478']
			username:   'user'
			credential: 'secret'
		},
	]
)!
```

A relayed pair is the last resort - it costs the relay's bandwidth and adds a
hop - so ICE only settles on one when nothing direct works. To force it, for
testing or for privacy, set `ice_gather_policy: .relay_only`; to keep local
addresses off the wire while still trying a direct path, use `.no_host`.

`turn` can also be used on its own: `turn.Client` allocates, creates
permissions, binds channels, and sends and receives, with the allocation kept
alive for you.

### Connect two peers with ICE

The ICE agent gathers candidates, exchanges them through whatever signalling you
already have, and gives you a datagram channel over whichever path worked.

```v
import time
import webrtc.ice

fn main() {
	mut agent := ice.Agent.new(
		role:         .controlling
		stun_servers: ['stun.l.google.com:19302']
	)!
	defer { agent.close() }

	// Hand these to the peer over your signalling channel.
	ufrag, pwd := agent.local_credentials()
	println('local credentials: ${ufrag} / ${pwd}')

	// And take the peer's in return.
	agent.set_remote_credentials(remote_ufrag, remote_pwd)!

	// Gathering opens the sockets and discovers reflexive addresses.
	agent.gather()!
	for candidate in agent.local_candidates() {
		signal_to_peer('a=candidate:${candidate}')
	}

	// Candidates from the peer can arrive at any time (trickle ICE).
	agent.add_remote_candidate_string(line_from_peer)!

	agent.connect(30 * time.second)!
	agent.send('hello'.bytes())!
	println(agent.recv(5 * time.second)!.bytestr())
}
```

For a complete runnable version, see
[`examples/ice-loopback`](examples/ice-loopback), and for the same thing with
DTLS and SRTP on top, [`examples/ice-dtls`](examples/ice-dtls).

### Secure the path with DTLS

The ICE agent is a datagram transport, which is all `dtls.Conn` needs. The
handshake authenticates the peer against the fingerprint from signalling and
exports the keys SRTP uses.

```v
import webrtc.dtls

fn main() {
	certificate := dtls.Certificate.generate()!
	// Publish this in your offer as a=fingerprint.
	println('a=fingerprint:${certificate.fingerprint(.sha256)}')

	mut conn := dtls.Conn.new(agent,
		role:                .client
		certificate:         certificate
		remote_fingerprints: [dtls.Fingerprint.parse(peer_fingerprint_line)!]
	)!
	conn.handshake()!

	// Two SRTP contexts, keyed from the handshake and pointed the right ways.
	mut outbound, mut inbound := conn.srtp_contexts()!
	protected := outbound.protect_rtp(packet.marshal()!)!
}
```

### Open a data channel

SCTP runs inside the DTLS connection, and a data channel is one SCTP stream pair.

```v
import webrtc.datachannel
import webrtc.sctp

fn main() {
	// The DTLS client is the SCTP client (RFC 8841), so the role passes through.
	mut association := sctp.Association.new(dtls_conn, role: .client)!
	association.connect(20 * time.second)!

	mut channels := datachannel.Manager.new(association, is_dtls_client: true)
	mut chat := channels.create('chat', datachannel.ChannelOptions{}, 10 * time.second)!

	chat.send_text('hello')!
	println(chat.recv(5 * time.second)!.text())

	// Unordered and partially reliable, for latency-sensitive traffic.
	mut fast := channels.create('fast', datachannel.ChannelOptions{
		ordered:         false
		max_retransmits: u16(0)
	}, 10 * time.second)!
}
```

The other end takes them with `channels.accept(timeout)`.

### Discover your public address

```v
import webrtc.stunclient

fn main() {
	addr := stunclient.discover('stun.l.google.com:19302')!
	println('the internet sees me as ${addr}')
}
```

### Parse an offer

```v
import webrtc.sdp

fn main() {
	offer := sdp.parse(offer_text)!
	for media in offer.media_descriptions {
		mid := media.mid() or { '?' }
		println('${media.media} (mid ${mid}) is ${media.direction()}')
		for codec in media.rtpmaps() {
			println('  ${codec.payload_type}: ${codec.encoding_name}/${codec.clock_rate}')
		}
	}
}
```

### Build and parse RTP

```v
import webrtc.rtp

fn main() {
	mut packet := rtp.Packet{
		header:  rtp.Header{
			payload_type:    96
			sequence_number: 1234
			timestamp:       90000
			ssrc:            0xCAFEBABE
			marker:          true
		}
		payload: frame
	}
	packet.header.set_extension(1, [u8(0x80)])!

	wire := packet.marshal()!
	back := rtp.Packet.decode(wire)!
	assert back.payload == frame
}
```

More examples are in [`examples/`](examples).

## Architecture

The stack is a set of independent modules with an explicit dependency order.
Nothing above reaches down past its neighbour, and the codec modules have no I/O
at all:

```
                 ┌─────────────┐
                 │  webrtc     │  RTCPeerConnection, JSEP
                 └──────┬──────┘
        ┌───────────────┼───────────────┐
   ┌────▼────┐   ┌──────▼──────┐  ┌─────▼─────┐
   │  ice    │   │    dtls     │  │   sctp    │──> datachannel
   └────┬────┘   └──────┬──────┘  └─────┬─────┘
        │               │               │
   ┌────▼────┐     ┌────▼────┐          │
   │  stun   │     │  srtp   │──────────┘
   └────┬────┘     └────┬────┘
        │          ┌────▼────┬─────────┐
        │          │   rtp   │  rtcp   │
        │          └─────────┴─────────┘
   ┌────▼──────────────────────────────┐
   │ netaddr · transport · logging     │
   └───────────────────────────────────┘
```

Why the split matters, and the reasoning behind the concurrency model, error
handling and resource limits, is in the header comment of each module.

## Development

```sh
make test        # run the test suite
make fmt         # format
make check       # fmt verification, vet and tests
make examples    # build every example
```

Or, without make:

```sh
v test .
v fmt -verify .
v vet .
```

The tests are not only unit tests over byte slices. `ice`, `stunclient` and the
transport layer open real sockets on loopback and drive two agents through a
complete exchange, because the interesting failures in this domain are in
timing, state transitions and concurrency, and those do not show up in a
pure-function test.

Contributions are welcome; please read
[CONTRIBUTING.md](CONTRIBUTING.md) first.
