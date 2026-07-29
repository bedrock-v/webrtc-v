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