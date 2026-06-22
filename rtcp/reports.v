module rtcp

import webrtc.internal.codec

// reception_report_size is the fixed size of one report block.
pub const reception_report_size = 24

// ReceptionReport is one report block: what a receiver observed about one
// synchronisation source (RFC 3550 section 6.4.1).
pub struct ReceptionReport {
pub mut:
	// ssrc identifies the source this block describes.
	ssrc u32
	// fraction_lost is the loss fraction since the previous report, as a
	// fixed-point number with the binary point at the left edge: 256 means all
	// packets lost.
	fraction_lost u8
	// total_lost is the cumulative loss count, a 24-bit signed quantity.
	// Duplicates can make it go down, which is why it is signed.
	total_lost i32
	// last_sequence_number is the highest sequence number received, with the
	// roll-over count in the top 16 bits.
	last_sequence_number u32
	// jitter is the interarrival jitter estimate in timestamp units.
	jitter u32
	// last_sender_report is the middle 32 bits of the NTP timestamp from the
	// most recent sender report received from this source.
	last_sender_report u32
	// delay is the time between receiving that sender report and sending this
	// block, in units of 1/65536 seconds. The sender combines the two to
	// compute a round-trip time.
	delay u32
}