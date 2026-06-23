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