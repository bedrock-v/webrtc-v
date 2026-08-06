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

fn test_packet_rejects_malformed_input() {
	Packet.decode([]u8{len: 4}, default_max_chunks) or {
		assert err is DecodeError
		if err is DecodeError {
			assert err.reason == .too_short
		}
		return
	}
	assert false, 'a short packet must be rejected'
}

fn test_chunk_length_below_the_header_is_rejected() {
	// A length under four would make the chunk walker loop forever, which is
	// exactly what a hostile peer would send.
	unmarshal_chunks([u8(0x0B), 0x00, 0x00, 0x02], default_max_chunks) or {
		assert err is DecodeError
		if err is DecodeError {
			assert err.reason == .bad_length
		}
		return
	}
	assert false, 'a chunk length below the header size must be rejected'
}

fn test_chunk_count_is_bounded() {
	mut chunks := []RawChunk{}
	for _ in 0 .. 20 {
		chunks << RawChunk{
			typ: u8(ChunkType.cookie_ack)
		}
	}
	raw := Packet{
		verification_tag: 1
		chunks:           chunks
	}.marshal()!

	Packet.decode(raw, 5) or {
		assert err is DecodeError
		// The same bytes decode fine under a larger limit.
		Packet.decode(raw, default_max_chunks)!
		return
	}
	assert false, 'the chunk count limit must be enforced'
}