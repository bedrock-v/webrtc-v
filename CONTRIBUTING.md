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
