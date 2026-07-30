module sctp

import webrtc.internal.codec

// SCTP chunks (RFC 4960 section 3.2).
//
// Every chunk is type, flags, a 16-bit length that counts the four header bytes
// but not the padding, and a value padded to a four-byte boundary. Several
// chunks travel in one packet, which is how an association acknowledges data
// and sends more in the same datagram.

// chunk_header_size is the four-byte type, flags and length.
pub const chunk_header_size = 4

// ChunkType identifies a chunk. The values are from the IANA SCTP Chunk Types
// registry; the ones here are those a WebRTC data channel needs.
pub enum ChunkType as u8 {
	data              = 0
	init              = 1
	init_ack          = 2
	sack              = 3
	heartbeat         = 4
	heartbeat_ack     = 5
	abort             = 6
	shutdown          = 7
	shutdown_ack      = 8
	error             = 9
	cookie_echo       = 10
	cookie_ack        = 11
	ecne              = 12
	cwr               = 13
	shutdown_complete = 14
	// reconfig re-negotiates streams (RFC 6525). WebRTC uses it to close an
	// individual data channel without tearing down the association.
	reconfig = 130
	// forward_tsn skips over messages abandoned by partial reliability
	// (RFC 3758). Without it, a receiver waiting for an abandoned message would
	// stall the stream forever.
	forward_tsn = 192
}

pub fn (t ChunkType) str() string {
	return match t {
		.data { 'DATA' }
		.init { 'INIT' }
		.init_ack { 'INIT_ACK' }
		.sack { 'SACK' }
		.heartbeat { 'HEARTBEAT' }
		.heartbeat_ack { 'HEARTBEAT_ACK' }
		.abort { 'ABORT' }
		.shutdown { 'SHUTDOWN' }
		.shutdown_ack { 'SHUTDOWN_ACK' }
		.error { 'ERROR' }
		.cookie_echo { 'COOKIE_ECHO' }
		.cookie_ack { 'COOKIE_ACK' }
		.ecne { 'ECNE' }
		.cwr { 'CWR' }
		.shutdown_complete { 'SHUTDOWN_COMPLETE' }
		.reconfig { 'RECONFIG' }
		.forward_tsn { 'FORWARD_TSN' }
	}
}

fn chunk_type_from_value(v u8) ?ChunkType {
	return match v {
		0 { ChunkType.data }
		1 { ChunkType.init }
		2 { ChunkType.init_ack }
		3 { ChunkType.sack }
		4 { ChunkType.heartbeat }
		5 { ChunkType.heartbeat_ack }
		6 { ChunkType.abort }
		7 { ChunkType.shutdown }
		8 { ChunkType.shutdown_ack }
		9 { ChunkType.error }
		10 { ChunkType.cookie_echo }
		11 { ChunkType.cookie_ack }
		12 { ChunkType.ecne }
		13 { ChunkType.cwr }
		14 { ChunkType.shutdown_complete }
		130 { ChunkType.reconfig }
		192 { ChunkType.forward_tsn }
		else { none }
	}
}

// unrecognised_chunk_action says what a receiver must do with a chunk type it
// does not know, which the top two bits of the type encode
// (RFC 4960 section 3.2).
//
// Getting this right is what lets the protocol be extended: an endpoint that
// meets a chunk from a newer specification either skips it or aborts, and the
// sender can tell which by choosing the type number.
pub enum UnrecognisedAction {
	// stop_processing: discard the packet and stop.
	stop_processing
	// stop_and_report: discard, stop, and report the unrecognised type.
	stop_and_report
	// skip: ignore this chunk and carry on with the rest of the packet.
	skip
	// skip_and_report: ignore it, carry on, and report it.
	skip_and_report
}

pub fn unrecognised_chunk_action(typ u8) UnrecognisedAction {
	return match typ >> 6 {
		0 { UnrecognisedAction.stop_processing }
		1 { UnrecognisedAction.stop_and_report }
		2 { UnrecognisedAction.skip }
		else { UnrecognisedAction.skip_and_report }
	}
}

// DecodeError describes why a byte string is not a valid SCTP packet or chunk.
pub struct DecodeError {
pub:
	reason DecodeReason
	detail string
}

pub enum DecodeReason {
	too_short
	bad_checksum
	bad_length
	bad_value
	unknown_chunk
	too_many_chunks
}

pub fn (e DecodeError) msg() string {
	return 'sctp: ${e.reason}: ${e.detail}'
}

pub fn (e DecodeError) code() int {
	return int(e.reason) + 1
}

// EncodeError is returned when a chunk cannot be represented on the wire.
pub struct EncodeError {
pub:
	detail string
}

pub fn (e EncodeError) msg() string {
	return 'sctp: ${e.detail}'
}

pub fn (e EncodeError) code() int {
	return 20
}

// RawChunk is a chunk as it appears on the wire: a type, flags, and the value
// bytes with the padding already stripped.
pub struct RawChunk {
pub:
	typ   u8
	flags u8
	value []u8
}

// chunk_type returns the decoded type, or none for one this implementation does
// not know.
pub fn (c RawChunk) chunk_type() ?ChunkType {
	return chunk_type_from_value(c.typ)
}

// name returns a readable name for diagnostics.
pub fn (c RawChunk) name() string {
	if typ := c.chunk_type() {
		return typ.str()
	}
	return 'chunk ${c.typ}'
}

// padded_len is the number of bytes the chunk occupies on the wire.
@[inline]
pub fn (c RawChunk) padded_len() int {
	return padded_size(chunk_header_size + c.value.len)
}

@[inline]
fn padded_size(n int) int {
	rem := n % 4
	if rem == 0 {
		return n
	}
	return n + (4 - rem)
}

// marshal_chunk writes one chunk, including its padding.
fn marshal_chunk(mut w codec.Writer, typ u8, flags u8, value []u8) ! {
	total := chunk_header_size + value.len
	if total > 0xFFFF {
		return EncodeError{
			detail: 'chunk of ${total} bytes exceeds the 16-bit length field'
		}
	}
	w.u8(typ)
	w.u8(flags)
	// The length counts the header and the value, but never the padding.
	w.u16(u16(total))
	w.bytes(value)
	w.pad(4)
}

// unmarshal_chunks decodes every chunk in a packet body.
pub fn unmarshal_chunks(body []u8, max_chunks int) ![]RawChunk {
	mut out := []RawChunk{}
	mut r := codec.Reader.new(body)

	for r.remaining() > 0 {
		if out.len >= max_chunks {
			return DecodeError{
				reason: .too_many_chunks
				detail: 'more than ${max_chunks} chunks in one packet'
			}
		}
		if r.remaining() < chunk_header_size {
			return DecodeError{
				reason: .bad_length
				detail: '${r.remaining()} trailing bytes are not a chunk header'
			}
		}
		typ := r.u8('chunk type')!
		flags := r.u8('chunk flags')!
		length := int(r.u16('chunk length')!)

		if length < chunk_header_size {
			// A length below the header size would make the reader loop
			// forever, which is exactly what a hostile peer would send.
			return DecodeError{
				reason: .bad_length
				detail: 'chunk declares a length of ${length}, below the ${chunk_header_size}-byte header'
			}
		}
		value_length := length - chunk_header_size
		value := r.bytes(value_length, 'chunk value') or {
			return DecodeError{
				reason: .bad_length
				detail: 'chunk declares ${value_length} value bytes but only ${r.remaining()} remain'
			}
		}
		// Padding follows every chunk except, possibly, the last one in a
		// packet. Being tolerant of a missing final pad costs nothing.
		pad := padded_size(length) - length
		if pad > 0 && r.remaining() >= pad {
			r.skip(pad, 'chunk padding')!
		}

		out << RawChunk{
			typ:   typ
			flags: flags
			value: value
		}
	}
	return out
}
