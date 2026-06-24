module rtcp

import webrtc.internal.codec

// Transport-wide congestion control feedback (draft-holmer-rmcat-transport-wide
// -cc-extensions-01).
//
// The sender stamps every packet with a transport-wide sequence number in an
// RTP header extension; the receiver reports back, for each of those numbers,
// whether it arrived and when. Because the numbering spans every stream on the
// transport, one feedback message describes the whole connection, which is what
// lets a bandwidth estimator see the path rather than one stream at a time.
//
// The wire format is designed for density: statuses are run-length or
// bit-vector encoded, and arrival times are deltas in 250 microsecond ticks
// relative to a coarse 64 millisecond reference.

// delta_tick is the unit of the arrival-time deltas, in microseconds.
pub const delta_tick_micros = 250

// reference_time_unit_micros is the unit of the reference time field.
pub const reference_time_unit_micros = 64000

// max_transport_cc_packets bounds how many packet statuses one message may
// describe. The status count field is 16 bits, so a hostile peer could
// otherwise declare 65535 statuses and make the decoder allocate for all of
// them before discovering the message is truncated.
pub const max_transport_cc_packets = 4096

// PacketStatus is the per-packet symbol in a feedback message.
pub enum PacketStatus as u8 {
	// not_received: the packet never arrived.
	not_received = 0
	// received_small_delta: arrived, with a delta that fits one unsigned byte.
	received_small_delta = 1
	// received_large_delta: arrived, with a delta that needs a signed 16-bit
	// value - either a long gap or a reordering that makes it negative.
	received_large_delta = 2
	// reserved is not assigned. A peer that sends it is either buggy or
	// probing; the packet is rejected rather than guessed at.
	reserved = 3
}

// PacketFeedback is the report for one transport sequence number.
pub struct PacketFeedback {
pub mut:
	sequence_number u16
	status          PacketStatus
	// delta_ticks is the arrival time relative to the previous received packet,
	// in 250 microsecond units. It is meaningless when status is not_received.
	delta_ticks i32
}

// TransportLayerCc is a 205 packet with FMT 15.
pub struct TransportLayerCc {
pub mut:
	sender_ssrc          u32
	media_ssrc           u32
	base_sequence_number u16
	// reference_time is a 24-bit value in 64 millisecond units. It wraps about
	// every 13 hours, so consumers must treat it as circular.
	reference_time u32
	// fb_packet_count increments per feedback message and lets a sender detect
	// that a feedback message was itself lost.
	fb_packet_count u8
	packets         []PacketFeedback
}

pub fn (t &TransportLayerCc) destination_ssrc() []u32 {
	return [t.media_ssrc]
}

// arrival_times_micros returns the absolute arrival time of each received packet
// in microseconds, relative to the message's reference time.
//
// Deltas accumulate, so a single corrupted delta shifts every later timestamp.
// The values are only meaningful relative to each other and to the reference,
// which itself wraps; do not treat them as a wall clock.
pub fn (t &TransportLayerCc) arrival_times_micros() map[u16]i64 {
	mut out := map[u16]i64{}
	mut now := i64(t.reference_time) * reference_time_unit_micros
	for packet in t.packets {
		if packet.status == .not_received {
			continue
		}
		now += i64(packet.delta_ticks) * delta_tick_micros
		out[packet.sequence_number] = now
	}
	return out
}

pub fn (t &TransportLayerCc) marshal() ![]u8 {
	if t.packets.len > 0xFFFF {
		return EncodeError{
			detail: '${t.packets.len} packet statuses exceed the 16-bit count field'
		}
	}
	if t.reference_time > 0xFFFFFF {
		return EncodeError{
			detail: 'reference time ${t.reference_time} does not fit 24 bits'
		}
	}

	mut chunks := codec.Writer.new()
	mut deltas := codec.Writer.new()
	mut i := 0
	for i < t.packets.len {
		if t.packets[i].status == .reserved {
			return EncodeError{
				detail: 'packet status "reserved" cannot be encoded'
			}
		}
		run := run_length_at(t.packets, i)
		// A run-length chunk covers up to 8191 packets in two bytes. It only
		// pays off once the run is longer than a status vector would hold.
		if run >= 8 {
			length := if run > 8191 { 8191 } else { run }
			chunks.u16((u16(t.packets[i].status) << 13) | u16(length))
			write_deltas(mut deltas, t.packets, i, length)!
			i += length
			continue
		}
		i += write_status_vector(mut chunks, mut deltas, t.packets, i)!
	}

	// The FCI is padded to a word boundary; the padding must be inside the
	// packet length, not appended after it, or the compound parser will read it
	// as another packet.
	mut fci := codec.Writer.with_capacity(8 + chunks.len() + deltas.len() + 4)
	fci.u16(t.base_sequence_number)
	fci.u16(u16(t.packets.len))
	fci.u24(t.reference_time)
	fci.u8(t.fb_packet_count)
	fci.bytes(chunks.buf)
	fci.bytes(deltas.buf)
	fci.pad(4)

	return marshal_feedback(pt_transport_feedback, fmt_transport_cc, t.sender_ssrc, t.media_ssrc,
		fci.buf)!
}