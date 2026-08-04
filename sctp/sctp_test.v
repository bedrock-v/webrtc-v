module sctp

import encoding.hex
import sync
import time
import webrtc.logging

// -- CRC-32c ---------------------------------------------------------------

fn test_crc32c_check_values() {
	// The check value from the CRC catalogue for CRC-32/ISCSI, plus the empty
	// string. Getting the polynomial wrong - using the IEEE one from the
	// standard library - produces a checksum every SCTP peer rejects, and this
	// is the only way to notice without a peer to talk to.
	assert crc32c([]u8{}) == 0x00000000
	assert crc32c('123456789'.bytes()) == 0xE3069283
	assert crc32c('a'.bytes()) == 0xC1D04330
	assert crc32c('The quick brown fox jumps over the lazy dog'.bytes()) == 0x22620404
}

fn test_crc32c_is_not_crc32() {
	// A guard against someone "simplifying" this to hash.crc32.
	assert crc32c('123456789'.bytes()) != 0xCBF43926
}

// -- Packets and chunks ----------------------------------------------------

fn test_packet_round_trip() {
	packet := Packet{
		verification_tag: 0xDEADBEEF
		chunks:           [
			RawChunk{
				typ:   u8(ChunkType.cookie_ack)
				value: []u8{}
			},
			RawChunk{
				typ:   u8(ChunkType.heartbeat)
				value: [u8(1), 2, 3]
			},
		]
	}
	raw := packet.marshal()!
	decoded := Packet.decode(raw, default_max_chunks)!

	assert decoded.verification_tag == 0xDEADBEEF
	assert decoded.source_port == webrtc_port
	assert decoded.chunks.len == 2
	assert decoded.chunks[0].chunk_type()? == .cookie_ack
	assert decoded.chunks[1].value == [u8(1), 2, 3]
}

fn test_packet_checksum_is_verified() {
	packet := Packet{
		verification_tag: 1
		chunks:           [
			RawChunk{
				typ:   u8(ChunkType.cookie_ack)
				value: []u8{}
			},
		]
	}
	raw := packet.marshal()!

	// Flipping any byte must be caught, including one inside the checksum
	// field itself.
	for i in 0 .. raw.len {
		mut tampered := raw.clone()
		tampered[i] ^= 0x01
		Packet.decode(tampered, default_max_chunks) or { continue }
		assert false, 'flipping byte ${i} was not detected'
	}
}