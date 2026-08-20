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
