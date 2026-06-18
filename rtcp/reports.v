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

fn (r ReceptionReport) marshal_into(mut w codec.Writer) ! {
	if r.total_lost > 0x7FFFFF || r.total_lost < -0x800000 {
		return EncodeError{
			detail: 'cumulative loss ${r.total_lost} does not fit the 24-bit field'
		}
	}
	w.u32(r.ssrc)
	w.u8(r.fraction_lost)
	w.u24(u32(r.total_lost) & 0xFFFFFF)
	w.u32(r.last_sequence_number)
	w.u32(r.jitter)
	w.u32(r.last_sender_report)
	w.u32(r.delay)
}

fn decode_reception_report(mut r codec.Reader) !ReceptionReport {
	ssrc := r.u32('report ssrc')!
	fraction_lost := r.u8('fraction lost')!
	raw_lost := r.u24('cumulative lost')!
	// Sign-extend the 24-bit two's complement value.
	total_lost := if raw_lost & 0x800000 != 0 {
		i32(raw_lost) - 0x1000000
	} else {
		i32(raw_lost)
	}
	return ReceptionReport{
		ssrc:                 ssrc
		fraction_lost:        fraction_lost
		total_lost:           total_lost
		last_sequence_number: r.u32('highest sequence')!
		jitter:               r.u32('jitter')!
		last_sender_report:   r.u32('last sender report')!
		delay:                r.u32('delay')!
	}
}