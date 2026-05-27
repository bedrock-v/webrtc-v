module aes

import crypto.aes as vlib_aes
import crypto.cipher
import rand

// Tests for the block cipher and the two modes.
//
// Three kinds of check, because each catches something the others do not:
// published vectors prove the algorithm is the standard one, differential tests
// against the standard library prove it agrees with an independent
// implementation over inputs nobody chose, and the round trips prove the modes
// are inverses of each other.

fn hex_to_bytes(s string) []u8 {
	mut out := []u8{cap: s.len / 2}
	for i := 0; i + 1 < s.len; i += 2 {
		out << u8(s[i..i + 2].parse_uint(16, 8) or { panic('bad hex') })
	}
	return out
}

fn bytes_to_hex(b []u8) string {
	mut out := ''
	for value in b {
		out += value.hex_full()
	}
	return out
}