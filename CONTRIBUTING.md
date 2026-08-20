# Contributing

Thanks for considering it. This document covers what you need to know to get a
change merged.

## Getting set up

You need V 0.5.2 or newer.

```sh
git clone https://github.com/bedrock-v/webrtc-v
cd webrtc-v
ln -s "$PWD" ~/.vmodules/webrtc     # so `import webrtc.stun` resolves
make check                          # fmt, vet and the full test suite
```

The symlink is how V finds a module that is not installed. `make check` should
pass on a clean checkout; if it does not, that is a bug and worth an issue on its
own.

## Before you start

**For a bug fix**, just send the pull request. A failing test in the first commit
and the fix in the second makes review easy, but one commit is fine.

**For a new feature or a new protocol layer**, open an issue first. The scope of
this project is deliberately bounded - it transports media, it does not encode
it - and it is better to find out that something is out of scope before you
write it.

**For anything security-sensitive**, read [SECURITY.md](SECURITY.md) first. If
you have found a vulnerability, do not open a pull request that fixes it in
public; report it privately.

## What a good change looks like

### It is tested

Every change to protocol code needs tests. Concretely:

- A new decoder needs a round-trip test, tests for each way the input can be
  malformed, and an inclusion in the adversarial test that feeds it random bytes.
  It must not panic on anything.
- A new packet format that the RFC publishes test vectors for must be tested
  against them. Reproducing the vector byte for byte catches the errors that a
  self-consistent implementation cannot.
- A change to anything with state or timing needs a test that drives it over real
  sockets. Look at `ice/ice_test.v` and `stunclient/client_test.v` for the
  pattern.
- A bug fix needs a test that fails before it and passes after.

Tests are not a formality here. The failures that matter in this domain are in
timing, state transitions and hostile input, and none of them show up in code
review.

### It handles hostile input

Everything from the network is attacker-controlled. When you write a decoder:

- Read through `internal/codec.Reader`. Do not index a slice directly.
- Use `Reader.sub` for a length-delimited substructure, so the nested decoder
  cannot read past its own bounds.
- If a length field from the wire decides how much you allocate, give it a limit,
  make the limit a parameter, and document it on the constant itself.
- Return a typed error. Do not panic, and do not return a partially decoded
  structure.
