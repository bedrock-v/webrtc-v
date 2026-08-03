module sctp

import webrtc.internal.codec

// The SCTP common header and packet framing (RFC 4960 section 3.1).

// packet_header_size is the twelve-byte common header.
pub const packet_header_size = 12

// checksum_offset is where the CRC-32c sits in the header.
const checksum_offset = 8

// default_max_chunks bounds how many chunks one packet may carry. Each one is
// work for the receiver, and the count comes from a peer that has not
// necessarily been authenticated yet.
pub const default_max_chunks = 64

// webrtc_port is the SCTP port both ends of a WebRTC association use. The value
// carries no meaning - there is one association per DTLS connection - but
// RFC 8841 fixes it at 5000 and the `a=sctp-port` attribute carries it.
pub const webrtc_port = u16(5000)

// Packet is a decoded SCTP packet.
pub struct Packet {
pub mut:
	source_port      u16 = webrtc_port
	destination_port u16 = webrtc_port
	// verification_tag is the tag the peer chose in its INIT. Every packet in
	// an association carries it, and a packet with the wrong tag is discarded:
	// it is what stops a blind attacker from injecting into an association
	// whose ports it can guess.
	verification_tag u32
	chunks           []RawChunk
}

// marshal serialises a packet and computes its checksum.
pub fn (p &Packet) marshal() ![]u8 {
	mut w := codec.Writer.with_capacity(packet_header_size + 128)
	w.u16(p.source_port)
	w.u16(p.destination_port)
	w.u32(p.verification_tag)
	// The checksum is computed over the finished packet with this field zero,
	// so it is written as zero now and patched below.
	w.u32(0)

	for chunk in p.chunks {
		marshal_chunk(mut w, chunk.typ, chunk.flags, chunk.value)!
	}

	mut raw := w.take()
	checksum := crc32c(raw)
	// RFC 3309: the checksum goes into the field in little-endian order, unlike
	// every other field in the header.
	raw[checksum_offset] = u8(checksum)
	raw[checksum_offset + 1] = u8(checksum >> 8)
	raw[checksum_offset + 2] = u8(checksum >> 16)
	raw[checksum_offset + 3] = u8(checksum >> 24)
	return raw
}

// Packet.decode parses a packet and verifies its checksum.
pub fn Packet.decode(data []u8, max_chunks int) !Packet {
	if data.len < packet_header_size {
		return DecodeError{
			reason: .too_short
			detail: '${data.len} bytes is smaller than the ${packet_header_size}-byte header'
		}
	}

	mut r := codec.Reader.new(data)
	source_port := r.u16('source port')!
	destination_port := r.u16('destination port')!
	verification_tag := r.u32('verification tag')!
	received := (u32(data[checksum_offset]) | (u32(data[checksum_offset + 1]) << 8) | (u32(data[
		checksum_offset + 2]) << 16) | (u32(data[checksum_offset + 3]) << 24))
	r.skip(4, 'checksum')!

	// Recompute over a copy with the checksum zeroed, which is how the sender
	// computed it.
	mut zeroed := data.clone()
	for i in 0 .. 4 {
		zeroed[checksum_offset + i] = 0
	}
	expected := crc32c(zeroed)
	if received != expected {
		return DecodeError{
			reason: .bad_checksum
			detail: 'checksum 0x${received.hex()} does not match the computed 0x${expected.hex()}'
		}
	}

	chunks := unmarshal_chunks(r.rest_view(), max_chunks)!
	return Packet{
		source_port:      source_port
		destination_port: destination_port
		verification_tag: verification_tag
		chunks:           chunks
	}
}

pub fn (p &Packet) str() string {
	mut names := []string{cap: p.chunks.len}
	for chunk in p.chunks {
		names << chunk.name()
	}
	return 'SCTP tag=0x${p.verification_tag.hex()} [${names.join(', ')}]'
}
