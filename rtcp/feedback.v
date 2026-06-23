module rtcp

import webrtc.internal.codec

// Feedback packets all begin with the same two identifiers: the source sending
// the feedback and the source it is about. Only the FCI that follows differs.
struct FeedbackHeader {
	sender_ssrc u32
	media_ssrc  u32
}