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