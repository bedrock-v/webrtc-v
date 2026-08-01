module sctp

import webrtc.internal.codec

// The typed chunk bodies a WebRTC association exchanges.

// Parameter type numbers from the IANA SCTP registry.
pub const param_heartbeat_info = u16(1)
pub const param_ipv4_address = u16(5)
pub const param_ipv6_address = u16(6)
pub const param_state_cookie = u16(7)
pub const param_unrecognized = u16(8)
pub const param_cookie_preservative = u16(9)
pub const param_host_name = u16(11)
pub const param_supported_address_types = u16(12)
pub const param_outgoing_ssn_reset = u16(13)
pub const param_incoming_ssn_reset = u16(14)
pub const param_reconfig_response = u16(16)
pub const param_random = u16(0x8002)
pub const param_chunk_list = u16(0x8003)
pub const param_hmac_algorithm = u16(0x8004)
pub const param_padding = u16(0x8005)
pub const param_supported_extensions = u16(0x8008)
pub const param_forward_tsn_supported = u16(0xC000)

// data_chunk_fixed_size is the DATA chunk's fixed fields, before the user data:
// the TSN, the stream identifier and sequence number, and the payload protocol
// identifier.
pub const data_chunk_fixed_size = 12

// DATA chunk flags. The bits are the low three of the flags byte
// (RFC 4960 section 3.3.1).
pub const data_flag_end = u8(0x01)
pub const data_flag_beginning = u8(0x02)
pub const data_flag_unordered = u8(0x04)
pub const data_flag_immediate_sack = u8(0x08)

// Payload protocol identifiers for data channels (RFC 8831 section 8).
//
// SCTP itself does not care what these mean; they are what tells a receiver
// whether a message is a string or binary, and whether it is a data channel
// control message rather than user data.
pub const ppid_dcep = u32(50)
pub const ppid_string = u32(51)
pub const ppid_binary_partial = u32(52)
pub const ppid_binary = u32(53)
pub const ppid_string_partial = u32(54)
pub const ppid_string_empty = u32(56)
pub const ppid_binary_empty = u32(57)

// Parameter is a type-length-value inside a chunk.
pub struct Parameter {
pub:
	typ   u16
	value []u8
}

fn marshal_parameters(parameters []Parameter) ![]u8 {
	mut w := codec.Writer.new()
	for parameter in parameters {
		total := 4 + parameter.value.len
		if total > 0xFFFF {
			return EncodeError{
				detail: 'parameter of ${total} bytes exceeds the 16-bit length field'
			}
		}
		w.u16(parameter.typ)
		w.u16(u16(total))
		w.bytes(parameter.value)
		w.pad(4)
	}
	return w.buf
}

fn unmarshal_parameters(body []u8) ![]Parameter {
	mut out := []Parameter{}
	mut r := codec.Reader.new(body)
	for r.remaining() >= 4 {
		typ := r.u16('parameter type')!
		length := int(r.u16('parameter length')!)
		if length < 4 {
			return DecodeError{
				reason: .bad_length
				detail: 'parameter declares a length of ${length}, below its 4-byte header'
			}
		}
		value := r.bytes(length - 4, 'parameter value') or {
			return DecodeError{
				reason: .bad_length
				detail: 'parameter declares ${length - 4} value bytes but only ${r.remaining()} remain'
			}
		}
		pad := padded_size(length) - length
		if pad > 0 && r.remaining() >= pad {
			r.skip(pad, 'parameter padding')!
		}
		out << Parameter{
			typ:   typ
			value: value
		}
	}
	return out
}

// find_parameter returns the first parameter of the given type.
pub fn find_parameter(parameters []Parameter, typ u16) ?Parameter {
	for parameter in parameters {
		if parameter.typ == typ {
			return parameter
		}
	}
	return none
}

// Init is the body of an INIT or INIT_ACK chunk (RFC 4960 sections 3.3.2 and
// 3.3.3). The two have identical layouts and differ only in which parameters
// they carry.
pub struct Init {
pub mut:
	// initiate_tag is the verification tag the peer must put in every packet it
	// sends us. It is random and must never be zero: zero is reserved for the
	// packets that set up or tear down an association.
	initiate_tag u32
	// advertised_receiver_window is how many bytes we are willing to buffer.
	// It is SCTP's flow control, and it is what makes back pressure reach the
	// sending application instead of being absorbed by an unbounded queue.
	advertised_receiver_window u32
	outbound_streams           u16
	inbound_streams            u16
	initial_tsn                u32
	parameters                 []Parameter
}

fn (i Init) marshal() ![]u8 {
	if i.initiate_tag == 0 {
		return EncodeError{
			detail: 'the initiate tag must not be zero'
		}
	}
	if i.outbound_streams == 0 || i.inbound_streams == 0 {
		return EncodeError{
			detail: 'an association needs at least one stream in each direction'
		}
	}
	mut w := codec.Writer.new()
	w.u32(i.initiate_tag)
	w.u32(i.advertised_receiver_window)
	w.u16(i.outbound_streams)
	w.u16(i.inbound_streams)
	w.u32(i.initial_tsn)
	w.bytes(marshal_parameters(i.parameters)!)
	return w.buf
}

fn unmarshal_init(value []u8) !Init {
	mut r := codec.Reader.new(value)
	initiate_tag := r.u32('initiate tag') or { return short('INIT') }
	advertised := r.u32('a_rwnd') or { return short('INIT') }
	outbound := r.u16('outbound streams') or { return short('INIT') }
	inbound := r.u16('inbound streams') or { return short('INIT') }
	initial_tsn := r.u32('initial TSN') or { return short('INIT') }

	if initiate_tag == 0 {
		return DecodeError{
			reason: .bad_value
			detail: 'the peer sent a zero initiate tag'
		}
	}
	if outbound == 0 || inbound == 0 {
		return DecodeError{
			reason: .bad_value
			detail: 'the peer offered zero streams'
		}
	}

	return Init{
		initiate_tag:               initiate_tag
		advertised_receiver_window: advertised
		outbound_streams:           outbound
		inbound_streams:            inbound
		initial_tsn:                initial_tsn
		parameters:                 unmarshal_parameters(r.rest_view())!
	}
}

// supports_forward_tsn reports whether the peer advertised partial reliability.
//
// Without it, a message abandoned by `maxRetransmits` would leave a permanent
// hole in the stream and the receiver would wait for it forever.
pub fn (i &Init) supports_forward_tsn() bool {
	return find_parameter(i.parameters, param_forward_tsn_supported) != none
}

// state_cookie returns the opaque cookie from an INIT_ACK.
pub fn (i &Init) state_cookie() ?[]u8 {
	parameter := find_parameter(i.parameters, param_state_cookie)?
	return parameter.value
}

// Data is the body of a DATA chunk (RFC 4960 section 3.3.1).
pub struct Data {
pub mut:
	// tsn is the transmission sequence number, which orders and acknowledges
	// data across the whole association.
	tsn u32
	// stream_identifier selects the stream; a data channel is one stream pair.
	stream_identifier u16
	// stream_sequence_number orders messages within an ordered stream. It is
	// meaningless when unordered is set.
	stream_sequence_number u16
	// payload_protocol_identifier tells the receiver what the bytes are.
	payload_protocol_identifier u32
	user_data                   []u8
	// A message larger than one packet is split, with beginning set on the
	// first fragment and end on the last.
	beginning bool
	end       bool
	unordered bool
	// immediate_sack asks the receiver to acknowledge without delay, which cuts
	// latency for a small message at the cost of an extra packet.
	immediate_sack bool
}

fn (d Data) flags() u8 {
	mut flags := u8(0)
	if d.end {
		flags |= data_flag_end
	}
	if d.beginning {
		flags |= data_flag_beginning
	}
	if d.unordered {
		flags |= data_flag_unordered
	}
	if d.immediate_sack {
		flags |= data_flag_immediate_sack
	}
	return flags
}

fn (d Data) marshal() ![]u8 {
	if d.user_data.len == 0 {
		// RFC 4960 section 3.3.1 forbids an empty DATA chunk; a peer that
		// receives one must abort the association.
		return EncodeError{
			detail: 'a DATA chunk must carry at least one byte'
		}
	}
	mut w := codec.Writer.with_capacity(12 + d.user_data.len)
	w.u32(d.tsn)
	w.u16(d.stream_identifier)
	w.u16(d.stream_sequence_number)
	w.u32(d.payload_protocol_identifier)
	w.bytes(d.user_data)
	return w.buf
}

fn unmarshal_data(flags u8, value []u8) !Data {
	mut r := codec.Reader.new(value)
	tsn := r.u32('TSN') or { return short('DATA') }
	stream_identifier := r.u16('stream identifier') or { return short('DATA') }
	stream_sequence := r.u16('stream sequence') or { return short('DATA') }
	ppid := r.u32('payload protocol identifier') or { return short('DATA') }
	user_data := r.rest()

	if user_data.len == 0 {
		return DecodeError{
			reason: .bad_value
			detail: 'DATA chunk with no user data'
		}
	}
	return Data{
		tsn:                         tsn
		stream_identifier:           stream_identifier
		stream_sequence_number:      stream_sequence
		payload_protocol_identifier: ppid
		user_data:                   user_data
		beginning:                   flags & data_flag_beginning != 0
		end:                         flags & data_flag_end != 0
		unordered:                   flags & data_flag_unordered != 0
		immediate_sack:              flags & data_flag_immediate_sack != 0
	}
}

// GapAckBlock names a run of received TSNs above the cumulative acknowledgement,
// as an offset from it.
pub struct GapAckBlock {
pub:
	start u16
	end   u16
}

// Sack acknowledges data (RFC 4960 section 3.3.4).
pub struct Sack {
pub mut:
	// cumulative_tsn_ack is the highest TSN below which everything has arrived.
	cumulative_tsn_ack u32
	// advertised_receiver_window is how much room is left in the receive
	// buffer. A sender that ignores it will overrun the receiver.
	advertised_receiver_window u32
	gap_ack_blocks             []GapAckBlock
	duplicate_tsns             []u32
}

fn (s Sack) marshal() ![]u8 {
	if s.gap_ack_blocks.len > 0xFFFF || s.duplicate_tsns.len > 0xFFFF {
		return EncodeError{
			detail: 'too many gap blocks or duplicate TSNs for the 16-bit counts'
		}
	}
	mut w := codec.Writer.new()
	w.u32(s.cumulative_tsn_ack)
	w.u32(s.advertised_receiver_window)
	w.u16(u16(s.gap_ack_blocks.len))
	w.u16(u16(s.duplicate_tsns.len))
	for block in s.gap_ack_blocks {
		w.u16(block.start)
		w.u16(block.end)
	}
	for tsn in s.duplicate_tsns {
		w.u32(tsn)
	}
	return w.buf
}

fn unmarshal_sack(value []u8) !Sack {
	mut r := codec.Reader.new(value)
	cumulative := r.u32('cumulative TSN ack') or { return short('SACK') }
	advertised := r.u32('a_rwnd') or { return short('SACK') }
	gap_count := int(r.u16('gap block count') or { return short('SACK') })
	duplicate_count := int(r.u16('duplicate count') or { return short('SACK') })

	mut gaps := []GapAckBlock{cap: gap_count}
	for i in 0 .. gap_count {
		start := r.u16('gap block ${i} start') or {
			return DecodeError{
				reason: .bad_length
				detail: 'SACK declares ${gap_count} gap blocks but block ${i} is truncated'
			}
		}
		end := r.u16('gap block ${i} end') or { return short('SACK') }
		if end < start {
			return DecodeError{
				reason: .bad_value
				detail: 'SACK gap block ${i} ends before it starts'
			}
		}
		gaps << GapAckBlock{
			start: start
			end:   end
		}
	}

	mut duplicates := []u32{cap: duplicate_count}
	for i in 0 .. duplicate_count {
		duplicates << r.u32('duplicate ${i}') or {
			return DecodeError{
				reason: .bad_length
				detail: 'SACK declares ${duplicate_count} duplicates but entry ${i} is truncated'
			}
		}
	}

	return Sack{
		cumulative_tsn_ack:         cumulative
		advertised_receiver_window: advertised
		gap_ack_blocks:             gaps
		duplicate_tsns:             duplicates
	}
}

// ForwardTsn tells the receiver to give up on everything below a TSN, because
// the sender has abandoned it (RFC 3758 section 3.2).
pub struct ForwardTsn {
pub mut:
	new_cumulative_tsn u32
	// streams carries, for each affected ordered stream, the sequence number to
	// skip to. Without it an ordered stream would stall on the gap.
	streams []ForwardTsnStream
}