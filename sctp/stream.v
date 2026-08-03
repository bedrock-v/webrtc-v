module sctp

// Per-stream state.
//
// An association carries many independent streams. A data channel is one of
// them, and the point of the separation is that a large message on one stream
// does not head-of-line block a small one on another - reassembly and ordering
// are per stream, while acknowledgement and congestion control are per
// association.

// Message is a complete application message delivered out of a stream.
pub struct Message {
pub:
	stream_identifier u16
	// payload_protocol_identifier is what tells a data channel whether the
	// bytes are a string, binary, or a DCEP control message.
	payload_protocol_identifier u32
	data                        []u8
	unordered                   bool
}

// max_message_size bounds one reassembled message. The peer chooses how many
// fragments to send, so without a ceiling it could make us buffer without
// limit. RFC 8831 puts the WebRTC default at 64 KiB and browsers negotiate
// 256 KiB.
pub const default_max_message_size = 262144

// max_reassembly_fragments bounds how many fragments one message may take.
const max_reassembly_fragments = 4096