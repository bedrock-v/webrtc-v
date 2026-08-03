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