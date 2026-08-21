# An image with V and this library already linked, for trying it without
# installing a toolchain.
#
# It is a development and CI convenience, not a deployment artifact: this is a
# library, and nothing here is a service worth running in production. What it
# buys you is `docker run ghcr.io/bedrock-v/webrtc-v` connecting two peers in
# front of you, and a known-good environment to run the suite in.
#
# V is built from its default branch, not from the 0.5.2 release archive and not
# from `thevlang/vlang` (which is on 0.5.0). This code uses
# `crypto.ecdsa.PublicKey.uncompressed_bytes`, which landed after 0.5.2 was
# tagged, so the released archive cannot compile it.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential ca-certificates git libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/vlang/v /opt/v \
    && make -C /opt/v \
    && /opt/v/v symlink \
    && v version
