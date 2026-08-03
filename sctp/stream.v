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

fn (mut s InboundStream) reset() {
	s.partial.clear()
	s.ready.clear()
}

// accept folds one DATA chunk into the stream and returns any messages that
// became deliverable.
fn (mut s InboundStream) accept(data Data, max_message_size int) ![]Message {
	// A message that arrives whole is the common case and needs no buffering.
	if data.beginning && data.end {
		if data.user_data.len > max_message_size {
			return DecodeError{
				reason: .bad_value
				detail: 'message of ${data.user_data.len} bytes exceeds the ${max_message_size}-byte limit'
			}
		}
		message := Message{
			stream_identifier:           data.stream_identifier
			payload_protocol_identifier: data.payload_protocol_identifier
			data:                        data.user_data
			unordered:                   data.unordered
		}
		if data.unordered {
			return [message]
		}
		return s.deliver_ordered(data.stream_sequence_number, message)
	}

	mut partial := s.partial[data.stream_sequence_number] or {
		PartialMessage{
			payload_protocol_identifier: data.payload_protocol_identifier
			unordered:                   data.unordered
		}
	}
	if partial.fragments.len >= max_reassembly_fragments {
		return DecodeError{
			reason: .bad_value
			detail: 'message on stream ${data.stream_identifier} exceeds ${max_reassembly_fragments} fragments'
		}
	}
	if partial.total_bytes + data.user_data.len > max_message_size {
		return DecodeError{
			reason: .bad_value
			detail: 'message on stream ${data.stream_identifier} exceeds the ${max_message_size}-byte limit'
		}
	}

	if data.beginning {
		partial.seen_beginning = true
		partial.payload_protocol_identifier = data.payload_protocol_identifier
	}
	if data.end {
		partial.seen_end = true
	}
	partial.fragments << data.user_data
	partial.total_bytes += data.user_data.len
	s.partial[data.stream_sequence_number] = partial

	if !partial.seen_beginning || !partial.seen_end {
		return []Message{}
	}

	// The transmission sequence numbers guarantee the fragments arrive in
	// order, because the association only hands over chunks below the
	// cumulative acknowledgement point. Concatenating in arrival order is
	// therefore correct.
	mut body := []u8{cap: partial.total_bytes}
	for fragment in partial.fragments {
		body << fragment
	}
	s.partial.delete(data.stream_sequence_number)

	message := Message{
		stream_identifier:           data.stream_identifier
		payload_protocol_identifier: partial.payload_protocol_identifier
		data:                        body
		unordered:                   partial.unordered
	}
	if partial.unordered {
		return [message]
	}
	return s.deliver_ordered(data.stream_sequence_number, message)
}

// deliver_ordered releases a message and any successors that were waiting.
fn (mut s InboundStream) deliver_ordered(sequence u16, message Message) []Message {
	if sequence != s.next_sequence {
		// Out of order. Hold it; it will be released when the gap fills.
		s.ready[sequence] = message
		return []Message{}
	}
	mut out := [message]
	s.next_sequence++
	for {
		waiting := s.ready[s.next_sequence] or { break }
		out << waiting
		s.ready.delete(s.next_sequence)
		s.next_sequence++
	}
	return out
}

// skip_to advances the ordered sequence past messages the sender abandoned,
// which is what a FORWARD_TSN means for an ordered stream.
fn (mut s InboundStream) skip_to(sequence u16) []Message {
	// The comparison is on the wrapping 16-bit space, so a stream that has been
	// running long enough to wrap is not stalled by it.
	if !sequence_after(sequence, s.next_sequence) && sequence != s.next_sequence {
		return []Message{}
	}
	for s.next_sequence != sequence + 1 {
		s.partial.delete(s.next_sequence)
		s.ready.delete(s.next_sequence)
		s.next_sequence++
	}
	mut out := []Message{}
	for {
		waiting := s.ready[s.next_sequence] or { break }
		out << waiting
		s.ready.delete(s.next_sequence)
		s.next_sequence++
	}
	return out
}

// OutboundStream tracks the sequence numbering for one stream we send on.
struct OutboundStream {
mut:
	identifier    u16
	next_sequence u16
}

// next_sequence_number returns the number for the next ordered message.
// Unordered messages do not consume one.
fn (mut s OutboundStream) next_sequence_number() u16 {
	sequence := s.next_sequence
	s.next_sequence++
	return sequence
}

// sequence_after reports whether a is after b in the wrapping 16-bit stream
// sequence space.
@[inline]
fn sequence_after(a u16, b u16) bool {
	diff := u16(a - b)
	return diff != 0 && diff < 0x8000
}

// tsn_after reports whether a is after b in the wrapping 32-bit TSN space.
//
// Transmission sequence numbers wrap, and every comparison in the protocol -
// what to acknowledge, what to retransmit, what is a duplicate - depends on
// getting this right. A naive `>` stalls an association the moment it wraps.
@[inline]
fn tsn_after(a u32, b u32) bool {
	diff := u32(a - b)
	return diff != 0 && diff < 0x80000000
}