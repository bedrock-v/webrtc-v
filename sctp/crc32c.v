// Package sctp implements the Stream Control Transmission Protocol (RFC 4960)
// as WebRTC uses it: over DTLS, carrying data channels.
//
// SCTP is what gives a data channel its options. It provides reliable ordered
// delivery like TCP, and it also provides unordered delivery and partial
// reliability, which is what `ordered: false` and `maxRetransmits` in the
// browser API are built on. It multiplexes independent streams over one
// association, so a large file transfer on one channel does not head-of-line
// block a small control message on another.
module sctp