module rtcp

import webrtc.internal.codec

// Feedback packets all begin with the same two identifiers: the source sending
// the feedback and the source it is about. Only the FCI that follows differs.
struct FeedbackHeader {
	sender_ssrc u32
	media_ssrc  u32
}

fn decode_feedback_header(mut r codec.Reader, name string) !FeedbackHeader {
	sender := r.u32('sender ssrc') or { return short_packet(name) }
	media := r.u32('media ssrc') or { return short_packet(name) }
	return FeedbackHeader{
		sender_ssrc: sender
		media_ssrc:  media
	}
}

fn marshal_feedback(packet_type u8, fmt u8, sender_ssrc u32, media_ssrc u32, fci []u8) ![]u8 {
	mut body := codec.Writer.with_capacity(8 + fci.len)
	body.u32(sender_ssrc)
	body.u32(media_ssrc)
	body.bytes(fci)

	mut w := codec.Writer.with_capacity(header_size + body.len())
	header := Header{
		count:       fmt
		packet_type: packet_type
	}
	header.marshal_into(mut w, body.len())!
	w.bytes(body.buf)
	return w.buf
}

// PictureLossIndication asks the sender for a new key frame. It carries no
// detail about what was lost, which is why a decoder that can be more specific
// should send a FIR or a slice loss indication instead.
pub struct PictureLossIndication {
pub mut:
	sender_ssrc u32
	media_ssrc  u32
}

pub fn (p &PictureLossIndication) destination_ssrc() []u32 {
	return [p.media_ssrc]
}

pub fn (p &PictureLossIndication) marshal() ![]u8 {
	return marshal_feedback(pt_payload_feedback, fmt_pli, p.sender_ssrc, p.media_ssrc, []u8{})!
}

fn decode_pli(body []u8) !PictureLossIndication {
	mut r := codec.Reader.new(body)
	fb := decode_feedback_header(mut r, 'PictureLossIndication')!
	return PictureLossIndication{
		sender_ssrc: fb.sender_ssrc
		media_ssrc:  fb.media_ssrc
	}
}

// FirEntry names one source that should send a key frame.
pub struct FirEntry {
pub mut:
	ssrc u32
	// sequence_number distinguishes a repeated request from a new one. A sender
	// that sees the same value twice knows the request was retransmitted and
	// need not encode a second key frame.
	sequence_number u8
}

// FullIntraRequest asks specific sources for a key frame (RFC 5104 section 4.3).
pub struct FullIntraRequest {
pub mut:
	sender_ssrc u32
	media_ssrc  u32
	entries     []FirEntry
}

pub fn (f &FullIntraRequest) destination_ssrc() []u32 {
	mut out := []u32{cap: f.entries.len}
	for entry in f.entries {
		out << entry.ssrc
	}
	return out
}

pub fn (f &FullIntraRequest) marshal() ![]u8 {
	mut fci := codec.Writer.with_capacity(f.entries.len * 8)
	for entry in f.entries {
		fci.u32(entry.ssrc)
		fci.u8(entry.sequence_number)
		fci.u24(0)
	}
	return marshal_feedback(pt_payload_feedback, fmt_fir, f.sender_ssrc, f.media_ssrc, fci.buf)!
}

fn decode_fir(body []u8) !FullIntraRequest {
	mut r := codec.Reader.new(body)
	fb := decode_feedback_header(mut r, 'FullIntraRequest')!
	mut out := FullIntraRequest{
		sender_ssrc: fb.sender_ssrc
		media_ssrc:  fb.media_ssrc
	}
	for r.remaining() >= 8 {
		ssrc := r.u32('fir ssrc')!
		sequence_number := r.u8('fir sequence')!
		r.skip(3, 'fir reserved')!
		out.entries << FirEntry{
			ssrc:            ssrc
			sequence_number: sequence_number
		}
	}
	if r.remaining() != 0 {
		return DecodeError{
			reason: .bad_length
			detail: 'FullIntraRequest has ${r.remaining()} trailing bytes that are not a whole entry'
		}
	}
	return out
}

// NackPair is one FCI entry of a generic NACK: a sequence number plus a bitmask
// naming up to 16 more that follow it (RFC 4585 section 6.2.1).
pub struct NackPair {
pub mut:
	packet_id u16
	// lost_packets has bit i set when packet_id + i + 1 was also lost.
	lost_packets u16
}

// sequence_numbers expands the pair into the list of sequence numbers it names.
pub fn (n NackPair) sequence_numbers() []u16 {
	mut out := []u16{cap: 17}
	out << n.packet_id
	for i in 0 .. 16 {
		if n.lost_packets & (u16(1) << i) != 0 {
			out << n.packet_id + u16(i) + 1
		}
	}
	return out
}

// TransportLayerNack reports packets a receiver did not get, so the sender can
// retransmit them.
pub struct TransportLayerNack {
pub mut:
	sender_ssrc u32
	media_ssrc  u32
	nacks       []NackPair
}

pub fn (n &TransportLayerNack) destination_ssrc() []u32 {
	return [n.media_ssrc]
}

// sequence_numbers expands every pair into the full list of missing sequence
// numbers.
pub fn (n &TransportLayerNack) sequence_numbers() []u16 {
	mut out := []u16{}
	for pair in n.nacks {
		out << pair.sequence_numbers()
	}
	return out
}

// nack_pairs_from packs a sorted list of missing sequence numbers into the
// smallest set of NACK pairs that covers them.
//
// Each pair covers a 17-packet window, so a run of losses costs one pair rather
// than one entry per packet. The input must be sorted; unsorted input would
// still encode correctly but would waste pairs.
pub fn nack_pairs_from(sequence_numbers []u16) []NackPair {
	mut out := []NackPair{}
	mut i := 0
	for i < sequence_numbers.len {
		base := sequence_numbers[i]
		mut mask := u16(0)
		mut j := i + 1
		for j < sequence_numbers.len {
			offset := int(u16(sequence_numbers[j] - base))
			if offset < 1 || offset > 16 {
				break
			}
			mask |= u16(1) << (offset - 1)
			j++
		}
		out << NackPair{
			packet_id:    base
			lost_packets: mask
		}
		i = j
	}
	return out
}

pub fn (n &TransportLayerNack) marshal() ![]u8 {
	mut fci := codec.Writer.with_capacity(n.nacks.len * 4)
	for pair in n.nacks {
		fci.u16(pair.packet_id)
		fci.u16(pair.lost_packets)
	}
	return marshal_feedback(pt_transport_feedback, fmt_nack, n.sender_ssrc, n.media_ssrc, fci.buf)!
}

fn decode_nack(body []u8) !TransportLayerNack {
	mut r := codec.Reader.new(body)
	fb := decode_feedback_header(mut r, 'TransportLayerNack')!
	mut out := TransportLayerNack{
		sender_ssrc: fb.sender_ssrc
		media_ssrc:  fb.media_ssrc
	}
	for r.remaining() >= 4 {
		out.nacks << NackPair{
			packet_id:    r.u16('nack pid')!
			lost_packets: r.u16('nack blp')!
		}
	}
	if r.remaining() != 0 {
		return DecodeError{
			reason: .bad_length
			detail: 'TransportLayerNack has ${r.remaining()} trailing bytes that are not a whole pair'
		}
	}
	return out
}

// remb_identifier is the four-byte tag that distinguishes REMB from the other
// application-layer feedback messages sharing packet type 206 with FMT 15.
const remb_identifier = 'REMB'

// ReceiverEstimatedMaximumBitrate tells a sender how much bandwidth the
// receiver believes the path can carry.
//
// REMB is not an IETF standard - it is a Google draft that never advanced - but
// it is what browsers emitted before transport-wide congestion control, and
// interoperating with older endpoints still requires it.
pub struct ReceiverEstimatedMaximumBitrate {
pub mut:
	sender_ssrc u32
	// bitrate is in bits per second. It is transmitted as a 6-bit exponent and
	// an 18-bit mantissa, so only about 5.5 significant digits survive the
	// round trip.
	bitrate u64
	ssrcs   []u32
}

pub fn (r &ReceiverEstimatedMaximumBitrate) destination_ssrc() []u32 {
	return r.ssrcs.clone()
}