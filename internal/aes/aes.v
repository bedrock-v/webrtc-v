// Package aes is AES in the encryption direction, plus the two modes this
// project needs: CTR and GCM.
//
// It exists because `crypto.aes` in the standard library is a byte-oriented
// reference implementation, and the whole stack is built on top of AES - every
// DTLS record, every SRTP packet, and the SRTP key derivation. Measured on this
// machine in a `-prod` build, `crypto.aes` does about 3.8 MB/s of block
// encryption, which caps a data channel at roughly 2 MB/s. That is the ceiling
// for everything above it, so it is worth the table-driven version.
//
// Only the forward direction is here. CTR and GCM never decrypt a block - they
// encrypt a counter and exclusive-or it with the data - so the inverse cipher
// and its tables would be dead weight.
//
// **Timing.** The tables make this vulnerable to a cache-timing attack from an
// attacker running code on the same machine, and so is the S-box lookup in the
// standard library's version; this is not a regression, but it is also not
// constant time. See SECURITY.md.
module aes

// block_size is the AES block size in bytes. It is 16 for every key length.
pub const block_size = 16