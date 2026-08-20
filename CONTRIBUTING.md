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

### It respects the layering

The codec modules - `netaddr`, `stun`, `sdp`, `rtp`, `rtcp`, `srtp` - do not
import `net`. Adding an I/O dependency to one of them will be rejected; put the
networked part in `transport`, `stunclient` or `ice`. The reasoning, including a
V compiler bug that makes this more than a stylistic preference, is in the
header comment of `netaddr`.

### It is commented where it needs to be

Comments explain *why*. If a line implements a specific rule, name the RFC
section:

```v
// RFC 8445 section 7.2.2: the username is the peer's fragment followed by ours,
// so the receiver can tell which session the check belongs to before it has
// verified anything.
request.add_username('${a.remote_ufrag}:${a.local_ufrag}')!
```

Do not comment what the code already says. `// increment the counter` above
`i++` is noise.

Public API gets a doc comment whose first sentence starts with the identifier
being documented.

### It is formatted

`v fmt -w .` before committing. CI verifies it.

## Running the tests

```sh
make test                 # everything
v test stun               # one module
v test ice/ice_test.v     # one file
```

Some tests open loopback sockets and take a few seconds. If they are flaky on
your machine, say so in an issue rather than adding a sleep - a test that needs a
longer timeout to pass is usually telling you something.

`WEBRTC_LOG_LEVEL=debug` turns on the stack's logging, which is the fastest way
to see what an ICE agent is actually doing.

## Commit messages

Conventional commits, one purpose per commit:

```
feat(ice): learn peer-reflexive candidates from inbound checks
fix(srtp): advance the watermark on the first packet of a stream
docs(readme): correct the module status table
test(rtcp): add the RFC 4585 NACK vectors
```

Types in use: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`,
`chore`. The scope is the module name.

Keep the subject under 72 characters and in the imperative. If the change needs
explaining, put it in the body - what it does and why, not how.

## Pull requests

- One logical change per pull request. A refactor and a fix in the same diff is
  two pull requests.
- Do not reformat code you are not otherwise changing; it buries the real change
  and destroys `git blame`.
- Fill in the template. "What breaks if this is wrong" is the field reviewers
  read first.
- CI must be green. It runs the same `make check` you can run locally, on Linux
  and macOS.

Review is about correctness against the specification, safety against hostile
input, and whether the next person will understand it. Expect questions about
edge cases; they are not an objection to the change.

## If you found a better design

Say so, in an issue. Do not fold a redesign into an unrelated pull request. A
better idea is welcome; a large diff that changes several things at once is hard
to review and harder to revert.

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
