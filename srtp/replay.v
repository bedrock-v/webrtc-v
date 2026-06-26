module srtp

// default_replay_window is the number of packets behind the highest seen index
// that a receiver will still accept. RFC 3711 section 3.3.2 recommends at least
// 64; browsers use 64 and 128 is a common tuning for lossy paths.
pub const default_replay_window = 64

// ReplayDetector rejects packets whose index has already been seen.
//
// Without it, an attacker who records a packet can replay it indefinitely: the
// authentication tag stays valid, because it authenticates the packet and not
// the moment it was sent. The detector is a sliding bitmask - one bit per index
// in the window below the highest index accepted so far.
//
// The window only moves forward when a packet is accepted, which means an
// attacker cannot advance it with a forged packet: authentication is verified
// first, and only an authentic packet ever reaches this check.
pub struct ReplayDetector {
mut:
	window_size u64
	// highest is the largest index accepted so far.
	highest u64
	// mask has bit i set when index (highest - i) has been seen. Bit 0 is
	// therefore the highest index itself.
	mask u64
	seen bool
}

// ReplayDetector.new returns a detector with the given window size, capped at
// the 64 indices a single mask word can track.
pub fn ReplayDetector.new(window_size int) ReplayDetector {
	mut size := u64(window_size)
	if size == 0 || size > 64 {
		size = 64
	}
	return ReplayDetector{
		window_size: size
	}
}