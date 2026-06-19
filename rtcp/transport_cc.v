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