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

// SenderReport is a 200 packet: the sender's clock and counters, plus what it
// has received from others.
pub struct SenderReport {
pub mut:
	ssrc u32
	// ntp_time is the wallclock time as a 64-bit NTP timestamp. Together with
	// rtp_time it lets a receiver align streams that use unrelated RTP clocks.
	ntp_time u64
	// rtp_time is the same instant expressed in this stream's RTP timestamp
	// units.
	rtp_time     u32
	packet_count u32
	octet_count  u32
	reports      []ReceptionReport
	// profile_extension carries any profile-specific trailer. It is preserved
	// so an unrecognised extension does not vanish on a re-marshal.
	profile_extension []u8
}

// destination_ssrc returns the sources this packet reports on.
pub fn (s &SenderReport) destination_ssrc() []u32 {
	mut out := []u32{cap: s.reports.len}
	for report in s.reports {
		out << report.ssrc
	}
	return out
}

pub fn (s &SenderReport) marshal() ![]u8 {
	if s.reports.len > 31 {
		return EncodeError{
			detail: '${s.reports.len} report blocks exceed the 31 the count field can express'
		}
	}
	if s.profile_extension.len % 4 != 0 {
		return EncodeError{
			detail: 'profile extension of ${s.profile_extension.len} bytes is not a whole number of words'
		}
	}
	mut body := codec.Writer.new()
	body.u32(s.ssrc)
	body.u64(s.ntp_time)
	body.u32(s.rtp_time)
	body.u32(s.packet_count)
	body.u32(s.octet_count)
	for report in s.reports {
		report.marshal_into(mut body)!
	}
	body.bytes(s.profile_extension)

	mut w := codec.Writer.with_capacity(header_size + body.len())
	header := Header{
		count:       u8(s.reports.len)
		packet_type: pt_sender_report
	}
	header.marshal_into(mut w, body.len())!
	w.bytes(body.buf)
	return w.buf
}

fn decode_sender_report(header Header, body []u8) !SenderReport {
	mut r := codec.Reader.new(body)
	mut sr := SenderReport{
		ssrc:         r.u32('ssrc') or { return short_packet('SenderReport') }
		ntp_time:     r.u64('ntp time') or { return short_packet('SenderReport') }
		rtp_time:     r.u32('rtp time') or { return short_packet('SenderReport') }
		packet_count: r.u32('packet count') or { return short_packet('SenderReport') }
		octet_count:  r.u32('octet count') or { return short_packet('SenderReport') }
	}
	sr.reports = []ReceptionReport{cap: int(header.count)}
	for i in 0 .. int(header.count) {
		sr.reports << decode_reception_report(mut r) or {
			return DecodeError{
				reason: .bad_length
				detail: 'SenderReport declares ${header.count} report blocks but block ${i} is truncated'
			}
		}
	}
	sr.profile_extension = r.rest()
	return sr
}

// ReceiverReport is a 201 packet, sent by an endpoint that is receiving but not
// sending on this synchronisation source.
pub struct ReceiverReport {
pub mut:
	ssrc              u32
	reports           []ReceptionReport
	profile_extension []u8
}

pub fn (rr &ReceiverReport) destination_ssrc() []u32 {
	mut out := []u32{cap: rr.reports.len}
	for report in rr.reports {
		out << report.ssrc
	}
	return out
}

pub fn (rr &ReceiverReport) marshal() ![]u8 {
	if rr.reports.len > 31 {
		return EncodeError{
			detail: '${rr.reports.len} report blocks exceed the 31 the count field can express'
		}
	}
	if rr.profile_extension.len % 4 != 0 {
		return EncodeError{
			detail: 'profile extension of ${rr.profile_extension.len} bytes is not a whole number of words'
		}
	}
	mut body := codec.Writer.new()
	body.u32(rr.ssrc)
	for report in rr.reports {
		report.marshal_into(mut body)!
	}
	body.bytes(rr.profile_extension)

	mut w := codec.Writer.with_capacity(header_size + body.len())
	header := Header{
		count:       u8(rr.reports.len)
		packet_type: pt_receiver_report
	}
	header.marshal_into(mut w, body.len())!
	w.bytes(body.buf)
	return w.buf
}

fn decode_receiver_report(header Header, body []u8) !ReceiverReport {
	mut r := codec.Reader.new(body)
	mut rr := ReceiverReport{
		ssrc: r.u32('ssrc') or { return short_packet('ReceiverReport') }
	}
	rr.reports = []ReceptionReport{cap: int(header.count)}
	for i in 0 .. int(header.count) {
		rr.reports << decode_reception_report(mut r) or {
			return DecodeError{
				reason: .bad_length
				detail: 'ReceiverReport declares ${header.count} report blocks but block ${i} is truncated'
			}
		}
	}
	rr.profile_extension = r.rest()
	return rr
}

fn short_packet(name string) DecodeError {
	return DecodeError{
		reason: .too_short
		detail: '${name} is shorter than its fixed fields require'
	}
}
