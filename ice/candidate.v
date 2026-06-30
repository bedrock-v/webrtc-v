// Package ice implements Interactive Connectivity Establishment (RFC 8445) and
// the SDP encoding of candidates (RFC 8839).
//
// ICE is how two endpoints behind NATs find a path to each other. Each side
// gathers the transport addresses it might be reachable on, exchanges them
// through signalling, and then probes every pairing with STUN until one works.
// The probes double as authentication: they carry a MESSAGE-INTEGRITY keyed
// with credentials that only the signalling channel could have carried, so an
// off-path attacker cannot answer them.
module ice