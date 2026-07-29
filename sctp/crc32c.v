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

// CRC-32c, the Castagnoli variant, is SCTP's packet checksum (RFC 3309).
//
// It is not the CRC-32 in the standard library: that one uses the IEEE
// polynomial, and using it here would produce a checksum every peer rejects.
// The two differ only in the polynomial, which is why the mistake is easy to
// make and impossible to notice without a peer to talk to.

// crc32c_polynomial is the Castagnoli polynomial in its reversed form, which is
// what a table-driven implementation that shifts right needs.
const crc32c_polynomial = u32(0x82F63B78)

// crc32c_table is the byte-at-a-time lookup table, built once at startup.
const crc32c_table = build_crc32c_table()

fn build_crc32c_table() []u32 {
	mut table := []u32{len: 256}
	for i in 0 .. 256 {
		mut value := u32(i)
		for _ in 0 .. 8 {
			if value & 1 != 0 {
				value = (value >> 1) ^ crc32c_polynomial
			} else {
				value >>= 1
			}
		}
		table[i] = value
	}
	return table
}