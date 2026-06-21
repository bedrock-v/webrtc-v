module rtcp

import webrtc.internal.codec

// RawPacket holds a packet this implementation does not decode.
//
// Keeping unknown packets rather than discarding them lets an application
// forward a compound datagram intact - which an SFU must do - and lets a new
// feedback type be handled above this package without changing it.
pub struct RawPacket {
pub mut:
	header Header
	body   []u8
}

pub fn (r &RawPacket) destination_ssrc() []u32 {
	// The first word of most packet bodies is a source identifier, but that is
	// a convention rather than a rule, so nothing is claimed for a packet whose
	// layout is unknown.
	return []u32{}
}

pub fn (r &RawPacket) marshal() ![]u8 {
	mut w := codec.Writer.with_capacity(header_size + r.body.len)
	r.header.marshal_into(mut w, r.body.len)!
	w.bytes(r.body)
	return w.buf
}

// Packet is any RTCP packet.
pub type Packet = ApplicationDefined
	| FullIntraRequest
	| Goodbye
	| PictureLossIndication
	| RawPacket
	| ReceiverEstimatedMaximumBitrate
	| ReceiverReport
	| SenderReport
	| SourceDescription
	| TransportLayerCc
	| TransportLayerNack

// marshal serialises any packet.
pub fn (p Packet) marshal() ![]u8 {
	return match p {
		SenderReport { p.marshal()! }
		ReceiverReport { p.marshal()! }
		SourceDescription { p.marshal()! }
		Goodbye { p.marshal()! }
		ApplicationDefined { p.marshal()! }
		PictureLossIndication { p.marshal()! }
		FullIntraRequest { p.marshal()! }
		TransportLayerNack { p.marshal()! }
		ReceiverEstimatedMaximumBitrate { p.marshal()! }
		TransportLayerCc { p.marshal()! }
		RawPacket { p.marshal()! }
	}
}

// destination_ssrc returns the synchronisation sources a packet is about.
pub fn (p Packet) destination_ssrc() []u32 {
	return match p {
		SenderReport { p.destination_ssrc() }
		ReceiverReport { p.destination_ssrc() }
		SourceDescription { p.destination_ssrc() }
		Goodbye { p.destination_ssrc() }
		ApplicationDefined { p.destination_ssrc() }
		PictureLossIndication { p.destination_ssrc() }
		FullIntraRequest { p.destination_ssrc() }
		TransportLayerNack { p.destination_ssrc() }
		ReceiverEstimatedMaximumBitrate { p.destination_ssrc() }
		TransportLayerCc { p.destination_ssrc() }
		RawPacket { p.destination_ssrc() }
	}
}

// DecodeOptions bounds what one datagram may cost to decode.
@[params]
pub struct DecodeOptions {
pub:
	max_packets int = max_packets_per_compound
	max_size    int = max_packet_size
}

// unmarshal decodes a datagram into the packets it carries.
//
// RTCP datagrams are compound: several packets are concatenated, and RFC 3550
// section 6.1 requires the first to be a report and the second an SDES. Those
// composition rules are not enforced here - a receiver that rejected a
// non-conforming datagram would interoperate badly, and several deployed
// stacks send reduced-size RTCP (RFC 5506) that deliberately breaks them.
// What is enforced is that every packet fits inside the datagram.
pub fn unmarshal(data []u8, opts DecodeOptions) ![]Packet {
	if data.len > opts.max_size {
		return DecodeError{
			reason: .bad_length
			detail: 'datagram of ${data.len} bytes exceeds the ${opts.max_size}-byte limit'
		}
	}

	mut out := []Packet{}
	mut offset := 0
	for offset < data.len {
		if out.len >= opts.max_packets {
			return DecodeError{
				reason: .too_many_packets
				detail: 'more than ${opts.max_packets} packets in one datagram'
			}
		}
		remaining := unsafe { data[offset..] }
		mut r := codec.Reader.new(remaining)
		header := decode_header(mut r)!

		total := header.byte_length()
		if total > remaining.len {
			return DecodeError{
				reason: .bad_length
				detail: 'packet declares ${total} bytes but only ${remaining.len} remain in the datagram'
			}
		}
		body := unsafe { remaining[header_size..total] }
		out << decode_packet(header, body)!
		offset += total
	}
	return out
}

fn decode_packet(header Header, body []u8) !Packet {
	match header.packet_type {
		pt_sender_report {
			return decode_sender_report(header, body)!
		}
		pt_receiver_report {
			return decode_receiver_report(header, body)!
		}
		pt_source_description {
			return decode_source_description(header, body)!
		}
		pt_goodbye {
			return decode_goodbye(header, body)!
		}
		pt_application_defined {
			return decode_application_defined(header, body)!
		}
		pt_transport_feedback {
			match header.count {
				fmt_nack { return decode_nack(body)! }
				fmt_transport_cc { return decode_transport_cc(body)! }
				else {}
			}
		}
		pt_payload_feedback {
			match header.count {
				fmt_pli {
					return decode_pli(body)!
				}
				fmt_fir {
					return decode_fir(body)!
				}
				fmt_application_layer {
					// Application-layer feedback shares a type with REMB and
					// with anything else a vendor invents, so a body that does
					// not carry the REMB tag falls through to RawPacket rather
					// than being rejected.
					if remb := decode_remb(body) {
						return remb
					}
				}
				else {}
			}
		}
		else {}
	}
	return RawPacket{
		header: header
		body:   body.clone()
	}
}