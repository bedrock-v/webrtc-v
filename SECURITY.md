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
