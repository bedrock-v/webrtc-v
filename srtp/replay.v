module srtp

// default_replay_window is the number of packets behind the highest seen index
// that a receiver will still accept. RFC 3711 section 3.3.2 recommends at least
// 64; browsers use 64 and 128 is a common tuning for lossy paths.
pub const default_replay_window = 64