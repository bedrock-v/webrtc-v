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