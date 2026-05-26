module aes

// Counter mode.
//
// SRTP's AES-CM profiles use this directly, and GCM uses it for the payload.
// The counter is a full 16-byte block incremented as a big-endian integer,
// which is what both specifications require.

// Ctr is a counter-mode keystream generator.
pub struct Ctr {
mut:
	cipher  &Cipher = unsafe { nil }
	counter []u8
	// block holds the current keystream block, and used how much of it has
	// already been consumed. Keeping the remainder is what lets a caller
	// encrypt in arbitrary-sized pieces without restarting the counter.
	block []u8
	used  int
}