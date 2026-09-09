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

// run_length_at returns how many consecutive packets from index i share a
// status. Only the status has to match: a run-length chunk still stores one
// delta per received packet in the delta section, so the deltas may differ.
fn run_length_at(packets []PacketFeedback, i int) int {
	status := packets[i].status
	mut n := 1
	for i + n < packets.len && packets[i + n].status == status {
		n++
	}
	return n
}

// write_status_vector emits one vector chunk and returns how many packets it
// covered.
//
// The one-bit form holds fourteen packets but can only distinguish "not
// received" from "received with a small delta". The two-bit form holds seven
// and can express everything, so it is used whenever a large delta appears in
// the window.
fn write_status_vector(mut chunks codec.Writer, mut deltas codec.Writer, packets []PacketFeedback, i int) !int {
	mut one_bit_capable := true
	mut window := packets.len - i
	if window > 14 {
		window = 14
	}
	for k in 0 .. window {
		if packets[i + k].status == .received_large_delta {
			one_bit_capable = false
			break
		}
	}

	if one_bit_capable {
		mut chunk := u16(0x8000)
		for k in 0 .. window {
			if packets[i + k].status == .received_small_delta {
				chunk |= u16(1) << (13 - k)
			}
		}
		chunks.u16(chunk)
		write_deltas(mut deltas, packets, i, window)!
		return window
	}

	mut count := packets.len - i
	if count > 7 {
		count = 7
	}
	mut chunk := u16(0xC000)
	for k in 0 .. count {
		chunk |= u16(packets[i + k].status) << (12 - k * 2)
	}
	chunks.u16(chunk)
	write_deltas(mut deltas, packets, i, count)!
	return count
}

fn write_deltas(mut deltas codec.Writer, packets []PacketFeedback, start int, count int) ! {
	for k in 0 .. count {
		packet := packets[start + k]
		match packet.status {
			.not_received {}
			.received_small_delta {
				if packet.delta_ticks < 0 || packet.delta_ticks > 255 {
					return EncodeError{
						detail: 'delta ${packet.delta_ticks} for sequence ${packet.sequence_number} does not fit a small delta'
					}
				}
				deltas.u8(u8(packet.delta_ticks))
			}
			.received_large_delta {
				if packet.delta_ticks < -32768 || packet.delta_ticks > 32767 {
					return EncodeError{
						detail: 'delta ${packet.delta_ticks} for sequence ${packet.sequence_number} does not fit a large delta'
					}
				}
				deltas.u16(u16(i16(packet.delta_ticks)))
			}
			.reserved {
				return EncodeError{
					detail: 'packet status "reserved" cannot be encoded'
				}
			}
		}
	}
}

fn decode_transport_cc(body []u8) !TransportLayerCc {
	mut r := codec.Reader.new(body)
	fb := decode_feedback_header(mut r, 'TransportLayerCc')!

	base := r.u16('base sequence number') or { return short_packet('TransportLayerCc') }
	count := int(r.u16('packet status count') or { return short_packet('TransportLayerCc') })
	reference_time := r.u24('reference time') or { return short_packet('TransportLayerCc') }
	fb_packet_count := r.u8('feedback packet count') or { return short_packet('TransportLayerCc') }

	if count > max_transport_cc_packets {
		return DecodeError{
			reason: .bad_value
			detail: 'feedback declares ${count} packet statuses, over the ${max_transport_cc_packets} limit'
		}
	}

	// Statuses come first, then the deltas they refer to, so the chunks must be
	// fully decoded before any delta can be read.
	mut statuses := []PacketStatus{cap: count}
	for statuses.len < count {
		chunk := r.u16('status chunk') or {
			return DecodeError{
				reason: .bad_length
				detail: 'feedback declares ${count} statuses but the chunks end after ${statuses.len}'
			}
		}
		if chunk & 0x8000 == 0 {
			status := unsafe { PacketStatus(u8((chunk >> 13) & 0x03)) }
			length := int(chunk & 0x1FFF)
			if length == 0 {
				return DecodeError{
					reason: .bad_value
					detail: 'run-length chunk with a zero run'
				}
			}
			for _ in 0 .. length {
				if statuses.len == count {
					break
				}
				statuses << status
			}
			continue
		}
		if chunk & 0x4000 == 0 {
			// One-bit symbols: fourteen of them.
			for k in 0 .. 14 {
				if statuses.len == count {
					break
				}
				bit := (chunk >> (13 - k)) & 0x01
				statuses << if bit == 1 {
					PacketStatus.received_small_delta
				} else {
					PacketStatus.not_received
				}
			}
			continue
		}
		// Two-bit symbols: seven of them.
		for k in 0 .. 7 {
			if statuses.len == count {
				break
			}
			statuses << unsafe { PacketStatus(u8((chunk >> (12 - k * 2)) & 0x03)) }
		}
	}

	mut out := TransportLayerCc{
		sender_ssrc:          fb.sender_ssrc
		media_ssrc:           fb.media_ssrc
		base_sequence_number: base
		reference_time:       reference_time
		fb_packet_count:      fb_packet_count
		packets:              []PacketFeedback{cap: count}
	}
	for i, status in statuses {
		mut delta := i32(0)
		match status {
			.not_received {}
			.received_small_delta {
				delta = i32(r.u8('small delta') or {
					return DecodeError{
						reason: .bad_length
						detail: 'feedback is missing the delta for sequence ${base + u16(i)}'
					}
				})
			}
			.received_large_delta {
				raw := r.u16('large delta') or {
					return DecodeError{
						reason: .bad_length
						detail: 'feedback is missing the delta for sequence ${base + u16(i)}'
					}
				}
				delta = i32(i16(raw))
			}
			.reserved {
				return DecodeError{
					reason: .bad_value
					detail: 'feedback uses the reserved packet status for sequence ${base + u16(i)}'
				}
			}
		}

		out.packets << PacketFeedback{
			sequence_number: base + u16(i)
			status:          status
			delta_ticks:     delta
		}
	}
	return out
}
