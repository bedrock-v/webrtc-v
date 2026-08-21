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
