module randutil

import crypto.rand

// Every identifier in the WebRTC stack that an attacker must not be able to
// guess - ICE credentials, STUN transaction IDs, DTLS randoms, SSRCs - is
// generated here, from the operating system CSPRNG. There is deliberately no
// math/rand fallback: a failure to read entropy is returned as an error rather
// than silently downgraded to a predictable source.

// Character sets from RFC 8839 section 5.4: ICE credentials are drawn from
// ice-char, which is ALPHA / DIGIT / '+' / '/'.
const ice_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.bytes()

const alphanumeric = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.bytes()

// bytes returns n cryptographically secure random bytes.
pub fn bytes(n int) ![]u8 {
	if n < 0 {
		return error('randutil: negative length ${n}')
	}
	if n == 0 {
		return []u8{}
	}
	return rand.bytes(n)!
}

// chars returns a random string of length n drawn uniformly from alphabet.
//
// Rejection sampling is used rather than a modulo reduction so that the
// distribution stays uniform even when the alphabet length does not divide 256.
// A biased ICE password would shrink the effective search space an off-path
// attacker has to cover.
pub fn chars(n int, alphabet []u8) !string {
	if alphabet.len == 0 {
		return error('randutil: empty alphabet')
	}
	if alphabet.len > 256 {
		return error('randutil: alphabet longer than 256 symbols')
	}
	if n <= 0 {
		return ''
	}

	// Largest multiple of alphabet.len that fits in a byte; values at or above
	// this are rejected and redrawn.
	limit := 256 - (256 % alphabet.len)

	mut out := []u8{len: n}
	mut filled := 0
	for filled < n {
		// Over-read slightly to keep the number of syscalls low even with
		// rejections.
		chunk := rand.bytes(n - filled + 8)!
		for b in chunk {
			if int(b) >= limit {
				continue
			}
			out[filled] = alphabet[int(b) % alphabet.len]
			filled++
			if filled == n {
				break
			}
		}
	}
	return out.bytestr()
}

// alphanumeric_string returns a random string of ASCII letters and digits.
pub fn alphanumeric_string(n int) !string {
	return chars(n, alphanumeric)
}

// ice_ufrag returns an ICE username fragment. RFC 8445 section 5.2.1 requires
// at least 24 bits of randomness; 4 ice-chars is the minimum length and 8 is
// what browsers emit, which keeps interop paths well trodden.
pub fn ice_ufrag() !string {
	return chars(8, ice_chars)
}