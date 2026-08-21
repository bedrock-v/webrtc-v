# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's [private vulnerability
reporting](https://github.com/bedrock-v/webrtc-v/security/advisories/new). If you
cannot use that, email **security@vedrock.dev** with `webrtc-v` in the subject.

Please include:

- The affected version or commit.
- What an attacker can do, and what position they need to be in to do it
  (on-path, off-path, a peer we have signalled with, an arbitrary host).
- A reproduction: a byte sequence, a test case, or a description precise enough
  to rebuild one.
- Anything you know about the impact - a panic, an out-of-bounds read, an
  unbounded allocation, a bypassed check.

You do not need a working exploit. A crashing input is a complete report.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 3 working days |
| Initial assessment, with a severity | 10 working days |
| Fix for a high or critical issue | 30 days from assessment |
| Fix for a low or medium issue | the next scheduled release |

If we cannot meet a target we will say so, and why, before it passes.

We will credit you in the advisory and the changelog unless you ask us not to.
We do not currently offer a bounty.

### Coordinated disclosure

We ask for 90 days from the acknowledgement before public disclosure, or until a
fix is released, whichever comes first. If a fix will take longer we will
explain why and agree a date with you. If an issue is being exploited in the
wild, tell us and we will move immediately.

## Supported versions

This project is pre-1.0. Only the latest release receives security fixes.

| Version | Supported |
|---|---|
| latest release | ✅ |
| anything older | ❌ |

## Scope

This library sits directly on the network and parses input from parties that
have not been authenticated yet. The following are in scope and we want to hear
about them:

- **Memory safety** - an out-of-bounds read or write, or a panic reachable from
  a network packet. Every decoder is expected to reject malformed input as an
  error; a panic is a bug even if V catches it.
- **Resource exhaustion** - an input that causes unbounded allocation, unbounded
  CPU, or unbounded growth of an internal data structure. Every decoder that
  allocates based on a length field from the wire has a documented ceiling; a way
  around one of them is a vulnerability.
- **Authentication bypass** - anything that makes the stack accept a packet it
  should have rejected. Specifically: a STUN message with a bad or missing
  MESSAGE-INTEGRITY treated as authentic, an SRTP packet with a bad tag
  decrypted, an ICE connectivity check from an unauthenticated source advancing
  a candidate pair, a DTLS certificate accepted that does not match the
  fingerprint the application supplied, or an SCTP packet accepted with the wrong
  verification tag.
- **Replay** - a captured packet accepted a second time, or a way to advance a
  replay window with a forged packet.
- **Weak or predictable randomness** - anything that makes a transaction ID, ICE
  credential, SSRC, tiebreaker, DTLS random, certificate serial or SCTP
  verification tag guessable.
- **Cryptographic misuse** - a repeated SRTP counter, a key derived with the
  wrong label, a non-constant-time comparison of a secret.
- **Information disclosure** - a local address or other host detail leaking to a
  peer that should not have received it, beyond what the ICE candidate exchange
  necessarily discloses.

### Out of scope

- Vulnerabilities in the V compiler or standard library. Report those to
  [vlang/v](https://github.com/vlang/v/issues); tell us too if the stack is
  affected and we will work around it.
- Denial of service that requires the attacker to already be on the path and
  able to drop packets. UDP offers no protection against that and neither can we.
- The fact that ICE discloses local IP addresses to the peer. That is what ICE
  is; use the `InterfaceOptions` filter to control which addresses are gathered.
- Attacks that require the application to hand the library secrets it should not
  have, or to disable the checks the library performs.
- Anything in the `inspirations/` directory, which is reference material and not
  part of the module.

## Security properties this library aims to provide

Stated plainly so that a deviation is recognisable as a bug:

1. No input from the network causes a panic, an out-of-bounds access, or an
   allocation not bounded by a documented limit.
2. An SRTP packet is authenticated before it is decrypted and before it touches
   the replay window. A packet that fails authentication changes no state.
3. An ICE connectivity check is authenticated with the peer's password before it
   can create a candidate, advance a pair, or be answered with anything other
   than an error.
4. A DTLS peer is accepted only when its certificate matches a fingerprint
   supplied by the application. Accepting any certificate requires setting
   `insecure_skip_fingerprint_verification` explicitly; a connection with
   neither is refused at construction.
5. An SCTP packet whose verification tag does not match the association is
   discarded without changing any state.
6. Values an attacker must not predict come from the operating system CSPRNG,
   with no fallback. That includes STUN transaction ids, ICE credentials and
   tiebreakers, SSRCs, DTLS randoms and certificate serials, and SCTP
   verification tags and initial sequence numbers.
7. Secrets are compared in constant time.

## Known limitations

These are design limits, not bugs, and are documented so nobody mistakes one for
a guarantee:

- **The stack is pre-1.0 and has not been independently audited.** Do not deploy
  it where a compromise would be serious without reviewing it yourself.
- **AES is table-driven and is not constant time.** `internal/aes` uses the
  standard round tables, so its memory access pattern depends on the key. An
  attacker able to run code on the same machine and observe the cache can, in
  principle, recover key material; an attacker on the network cannot. The
  standard library's implementation has the same property through its S-box
  lookup, so this is not a regression, but it is a real limit: on a machine where
  untrusted code runs beside this library, AES-NI through a vetted C
  implementation is the answer, and this project does not link one.
- **TURN over TLS is not implemented.** `turns:` is refused rather than
  downgraded to plain TURN, because a downgrade would put the long-term
  credentials on the wire in the clear. Plain `turn:` over UDP works, and its
  credentials are protected by MESSAGE-INTEGRITY rather than by encryption -
  which is what RFC 8656 specifies, and which means an observer sees the
  relayed traffic.
- **DTLS implements one cipher suite**, `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`. A
  peer with nothing else in common fails the handshake rather than falling back
  to something weaker, which is the right outcome but worth knowing before
  deploying against an old endpoint.
- **The SCTP state cookie is remembered rather than self-authenticating.** RFC
  4960 makes it a stateless authenticated blob so a server can resist a flood of
  forged INITs; here the association sits behind an authenticated DTLS connection
  with exactly one peer, so that flood cannot reach it. Using `sctp` over an
  unauthenticated transport would need the RFC's construction instead.
- **SASLprep is not implemented.** `stun.short_term_key` rejects passwords
  outside printable ASCII rather than normalising them, because two peers that
  normalise differently would derive different keys and fail with no diagnosable
  cause. ICE credentials are ASCII by construction, so this affects only
  non-ICE uses of STUN long-term credentials.
