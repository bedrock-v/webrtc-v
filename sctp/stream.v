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

// InboundStream reassembles and orders the messages arriving on one stream.
struct InboundStream {
mut:
	identifier u16
	// next_sequence is the stream sequence number expected next for ordered
	// delivery. Anything above it waits.
	next_sequence u16
	// partial holds the fragments of messages not yet complete, keyed by
	// stream sequence number. Unordered fragments are keyed the same way,
	// because RFC 4960 still numbers them for reassembly even though their
	// delivery is not ordered.
	partial map[u16]PartialMessage
	// ready holds complete ordered messages that arrived early and are waiting
	// for their predecessors.
	ready map[u16]Message
}

// PartialMessage accumulates the fragments of one message.
struct PartialMessage {
mut:
	payload_protocol_identifier u32
	unordered                   bool
	fragments                   [][]u8
	seen_beginning              bool
	seen_end                    bool
	total_bytes                 int
}