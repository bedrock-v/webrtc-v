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
