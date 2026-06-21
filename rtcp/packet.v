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