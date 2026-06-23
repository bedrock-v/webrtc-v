module rtcp

import encoding.hex

fn test_sender_report_round_trip() {
	sr := SenderReport{
		ssrc:         0x902f9e2e
		ntp_time:     0xda8bd1fcdddda05a
		rtp_time:     0xaaf4edd5
		packet_count: 10
		octet_count:  1000
		reports:      [
			ReceptionReport{
				ssrc:                 0xbc5e9a40
				fraction_lost:        0
				total_lost:           0
				last_sequence_number: 0x46e1
				jitter:               273
				last_sender_report:   0x9f36432
				delay:                150137
			},
		]
	}
	raw := sr.marshal()!
	assert raw[0] == 0x81 // version 2, one report block
	assert raw[1] == pt_sender_report

	packets := unmarshal(raw)!
	assert packets.len == 1
	decoded := packets[0] as SenderReport
	assert decoded.ssrc == sr.ssrc
	assert decoded.ntp_time == sr.ntp_time
	assert decoded.rtp_time == sr.rtp_time
	assert decoded.packet_count == 10
	assert decoded.octet_count == 1000
	assert decoded.reports.len == 1
	assert decoded.reports[0].ssrc == 0xbc5e9a40
	assert decoded.reports[0].jitter == 273
	assert decoded.destination_ssrc() == [u32(0xbc5e9a40)]
	assert decoded.marshal()!.hex() == raw.hex()
}

fn test_receiver_report_round_trip() {
	rr := ReceiverReport{
		ssrc:    0x902f9e2e
		reports: [
			ReceptionReport{
				ssrc:       0xbc5e9a40
				total_lost: 42
			},
			ReceptionReport{
				ssrc:       0x11223344
				total_lost: -7
			},
		]
	}
	raw := rr.marshal()!
	decoded := unmarshal(raw)![0] as ReceiverReport
	assert decoded.reports.len == 2
	assert decoded.reports[0].total_lost == 42
	// Cumulative loss is signed: duplicates can drive it negative.
	assert decoded.reports[1].total_lost == -7
	assert decoded.marshal()!.hex() == raw.hex()
}

fn test_reception_report_rejects_out_of_range_loss() {
	rr := ReceiverReport{
		reports: [ReceptionReport{
			total_lost: 0x800000
		}]
	}
	rr.marshal() or {
		assert err is EncodeError
		return
	}
	assert false, 'cumulative loss that overflows 24 bits must be rejected'
}

fn test_report_count_limit() {
	rr := ReceiverReport{
		reports: []ReceptionReport{len: 32}
	}
	rr.marshal() or {
		assert err is EncodeError
		return
	}
	assert false, 'more than 31 report blocks must be rejected'
}

fn test_source_description_round_trip() {
	sdes := SourceDescription{
		chunks: [
			SdesChunk{
				source: 0x10000000
				items:  [
					SdesItem{
						typ:  sdes_cname
						text: 'user@example.org'
					},
					SdesItem{
						typ:  sdes_tool
						text: 'webrtc-v'
					},
				]
			},
			SdesChunk{
				source: 0x20000000
				items:  [
					SdesItem{
						typ:  sdes_cname
						text: 'a'
					},
				]
			},
		]
	}
	raw := sdes.marshal()!
	assert raw.len % 4 == 0

	decoded := unmarshal(raw)![0] as SourceDescription
	assert decoded.chunks.len == 2
	assert decoded.chunks[0].cname()? == 'user@example.org'
	assert decoded.chunks[0].items.len == 2
	assert decoded.chunks[1].cname()? == 'a'
	assert decoded.destination_ssrc() == [u32(0x10000000), 0x20000000]
	assert decoded.marshal()!.hex() == raw.hex()
}

fn test_sdes_chunk_without_cname() {
	sdes := SourceDescription{
		chunks: [
			SdesChunk{
				source: 1
				items:  [SdesItem{
					typ:  sdes_tool
					text: 'x'
				}]
			},
		]
	}
	decoded := unmarshal(sdes.marshal()!)![0] as SourceDescription
	assert decoded.chunks[0].cname() == none
}

fn test_sdes_rejects_terminator_as_item() {
	sdes := SourceDescription{
		chunks: [
			SdesChunk{
				source: 1
				items:  [SdesItem{
					typ:  sdes_end
					text: 'x'
				}]
			},
		]
	}
	sdes.marshal() or {
		assert err is EncodeError
		return
	}
	assert false, 'item type 0 must be rejected'
}

fn test_goodbye_round_trip() {
	bye := Goodbye{
		sources: [u32(0x11111111), 0x22222222]
		reason:  'session ended'
	}
	raw := bye.marshal()!
	decoded := unmarshal(raw)![0] as Goodbye
	assert decoded.sources == [u32(0x11111111), 0x22222222]
	assert decoded.reason == 'session ended'
	assert decoded.marshal()!.hex() == raw.hex()

	// A goodbye with no reason is also valid.
	plain := Goodbye{
		sources: [u32(1)]
	}
	back := unmarshal(plain.marshal()!)![0] as Goodbye
	assert back.reason == ''
}

fn test_application_defined_round_trip() {
	app := ApplicationDefined{
		subtype: 5
		ssrc:    0xdeadbeef
		name:    'TEST'
		data:    [u8(1), 2, 3, 4]
	}
	raw := app.marshal()!
	decoded := unmarshal(raw)![0] as ApplicationDefined
	assert decoded.subtype == 5
	assert decoded.name == 'TEST'
	assert decoded.data == [u8(1), 2, 3, 4]

	bad := ApplicationDefined{
		name: 'TOOLONG'
	}
	bad.marshal() or { return }
	assert false, 'a name that is not 4 characters must be rejected'
}

fn test_picture_loss_indication_round_trip() {
	pli := PictureLossIndication{
		sender_ssrc: 0x11111111
		media_ssrc:  0x22222222
	}
	raw := pli.marshal()!
	assert raw.len == 12
	assert raw[0] == 0x81 // version 2, FMT 1
	assert raw[1] == pt_payload_feedback

	decoded := unmarshal(raw)![0] as PictureLossIndication
	assert decoded.sender_ssrc == 0x11111111
	assert decoded.media_ssrc == 0x22222222
	assert decoded.destination_ssrc() == [u32(0x22222222)]
}

fn test_full_intra_request_round_trip() {
	fir := FullIntraRequest{
		sender_ssrc: 0x11111111
		media_ssrc:  0x22222222
		entries:     [
			FirEntry{
				ssrc:            0x33333333
				sequence_number: 7
			},
			FirEntry{
				ssrc:            0x44444444
				sequence_number: 8
			},
		]
	}
	raw := fir.marshal()!
	decoded := unmarshal(raw)![0] as FullIntraRequest
	assert decoded.entries.len == 2
	assert decoded.entries[0].sequence_number == 7
	assert decoded.entries[1].ssrc == 0x44444444
	assert decoded.destination_ssrc() == [u32(0x33333333), 0x44444444]
	assert decoded.marshal()!.hex() == raw.hex()
}

fn test_nack_round_trip() {
	nack := TransportLayerNack{
		sender_ssrc: 0x11111111
		media_ssrc:  0x22222222
		nacks:       [NackPair{
			packet_id:    100
			lost_packets: 0b1010
		}]
	}
	raw := nack.marshal()!
	decoded := unmarshal(raw)![0] as TransportLayerNack
	assert decoded.nacks.len == 1
	// The bitmask names packet_id + i + 1 for each set bit.
	assert decoded.sequence_numbers() == [u16(100), 102, 104]
	assert decoded.marshal()!.hex() == raw.hex()
}

fn test_nack_pairs_packing() {
	// A run of losses inside one 17-packet window costs a single pair.
	pairs := nack_pairs_from([u16(10), 11, 12, 26, 27])
	assert pairs.len == 2
	assert pairs[0].packet_id == 10
	assert pairs[0].sequence_numbers() == [u16(10), 11, 12, 26]
	assert pairs[1].packet_id == 27

	// A gap wider than the window starts a new pair.
	wide := nack_pairs_from([u16(1), 100])
	assert wide.len == 2

	assert nack_pairs_from([]u16{}).len == 0
	assert nack_pairs_from([u16(5)])[0].lost_packets == 0
}

fn test_nack_pairs_wrap_around() {
	// The window is computed on wrapping 16-bit arithmetic, so a loss run that
	// straddles the wrap still packs into one pair.
	pairs := nack_pairs_from([u16(65534), 65535, 0, 1])
	assert pairs.len == 1
	assert pairs[0].sequence_numbers() == [u16(65534), 65535, 0, 1]
}

fn test_remb_round_trip() {
	remb := ReceiverEstimatedMaximumBitrate{
		sender_ssrc: 0x11111111
		bitrate:     2500000
		ssrcs:       [u32(0x33333333), 0x44444444]
	}
	raw := remb.marshal()!
	assert raw[1] == pt_payload_feedback
	assert raw[0] & 0x1F == fmt_application_layer
	assert raw[12..16].bytestr() == 'REMB'

	decoded := unmarshal(raw)![0] as ReceiverEstimatedMaximumBitrate
	assert decoded.ssrcs == [u32(0x33333333), 0x44444444]
	// The 18-bit mantissa loses precision on large values; the result must be
	// close and must never exceed the requested rate by more than one unit in
	// the last place.
	assert decoded.bitrate >= 2499000 && decoded.bitrate <= 2500000
}

fn test_remb_small_bitrate_is_exact() {
	// A value that fits the mantissa needs no exponent and survives exactly.
	remb := ReceiverEstimatedMaximumBitrate{
		bitrate: 262143
	}
	decoded := unmarshal(remb.marshal()!)![0] as ReceiverEstimatedMaximumBitrate
	assert decoded.bitrate == 262143
}

fn test_non_remb_application_feedback_stays_raw() {
	// Packet type 206 with FMT 15 is shared by REMB and anything else a vendor
	// invents. A body without the REMB tag must survive as a raw packet rather
	// than being rejected or misread.
	raw := hex.decode('8fce0003111111112222222241424344')!
	packets := unmarshal(raw)!
	assert packets.len == 1
	assert packets[0] is RawPacket
}

fn test_transport_cc_round_trip_mixed_statuses() {
	mut cc := TransportLayerCc{
		sender_ssrc:          0x11111111
		media_ssrc:           0x22222222
		base_sequence_number: 1000
		reference_time:       0x123456
		fb_packet_count:      42
	}
	statuses := [PacketStatus.received_small_delta, .received_small_delta, .not_received,
		.received_large_delta, .not_received, .received_small_delta, .received_large_delta]
	for i, status in statuses {
		delta := match status {
			.received_small_delta { i32(10 + i) }
			.received_large_delta { i32(-500 - i) }
			else { i32(0) }
		}
		cc.packets << PacketFeedback{
			sequence_number: u16(1000 + i)
			status:          status
			delta_ticks:     delta
		}
	}

	raw := cc.marshal()!
	assert raw.len % 4 == 0
	decoded := unmarshal(raw)![0] as TransportLayerCc

	assert decoded.base_sequence_number == 1000
	assert decoded.reference_time == 0x123456
	assert decoded.fb_packet_count == 42
	assert decoded.packets.len == cc.packets.len
	for i, packet in decoded.packets {
		assert packet.sequence_number == cc.packets[i].sequence_number
		assert packet.status == cc.packets[i].status
		assert packet.delta_ticks == cc.packets[i].delta_ticks
	}
}

fn test_transport_cc_long_run_uses_run_length_chunk() {
	mut cc := TransportLayerCc{
		base_sequence_number: 0
	}
	for i in 0 .. 300 {
		cc.packets << PacketFeedback{
			sequence_number: u16(i)
			status:          .not_received
		}
	}
	raw := cc.marshal()!
	// 300 statuses that all fit one run-length chunk: the FCI is the 8-byte
	// feedback header, 8 bytes of fixed fields and a single 2-byte chunk,
	// padded to a word.
	assert raw.len == header_size + 8 + 8 + 4

	decoded := unmarshal(raw)![0] as TransportLayerCc
	assert decoded.packets.len == 300
	for packet in decoded.packets {
		assert packet.status == .not_received
	}
}

fn test_transport_cc_arrival_times_accumulate() {
	cc := TransportLayerCc{
		base_sequence_number: 5
		reference_time:       1
		packets:              [
			PacketFeedback{
				sequence_number: 5
				status:          .received_small_delta
				delta_ticks:     4
			},
			PacketFeedback{
				sequence_number: 6
				status:          .not_received
			},
			PacketFeedback{
				sequence_number: 7
				status:          .received_small_delta
				delta_ticks:     8
			},
		]
	}
	times := cc.arrival_times_micros()
	assert times.len == 2
	assert times[u16(5)] == 64000 + 4 * 250
	assert times[u16(7)] == 64000 + 12 * 250
	assert u16(6) !in times
}

fn test_transport_cc_rejects_out_of_range_delta() {
	cc := TransportLayerCc{
		packets: [
			PacketFeedback{
				status:      .received_small_delta
				delta_ticks: 256
			},
		]
	}
	cc.marshal() or {
		assert err is EncodeError
		return
	}
	assert false, 'a small delta over 255 must be rejected'
}

fn test_transport_cc_rejects_reserved_status() {
	cc := TransportLayerCc{
		packets: [PacketFeedback{
			status: .reserved
		}]
	}
	cc.marshal() or {
		assert err is EncodeError
		return
	}
	assert false, 'the reserved status must not be encodable'
}

fn test_transport_cc_rejects_absurd_status_count() {
	// Declares 60000 statuses in a 20-byte packet.
	raw := hex.decode('af cd 0004 11111111 22222222 0000 ea60 000000 00'.replace(' ', ''))!
	unmarshal(raw) or {
		assert err is DecodeError
		return
	}
	assert false, 'an inflated status count must be rejected'
}

fn test_compound_datagram() {
	sr := SenderReport{
		ssrc: 1
	}
	sdes := SourceDescription{
		chunks: [
			SdesChunk{
				source: 1
				items:  [SdesItem{
					typ:  sdes_cname
					text: 'cname'
				}]
			},
		]
	}
	pli := PictureLossIndication{
		sender_ssrc: 1
		media_ssrc:  2
	}

	raw := marshal([Packet(sr), Packet(sdes), Packet(pli)])!
	packets := unmarshal(raw)!
	assert packets.len == 3
	assert packets[0] is SenderReport
	assert packets[1] is SourceDescription
	assert packets[2] is PictureLossIndication
	assert marshal(packets)!.hex() == raw.hex()
}

fn test_unmarshal_rejects_malformed_datagrams() {
	cases := {
		'empty header':           '80'
		'wrong version':          '40c80006' + '000000000000000000000000000000000000000000000000'
		'length past end':        '80c8ffff'
		'truncated report block': '81c8000c11111111' + '0000000000000000000000000000000000000000'
	}
	for name, encoded in cases {
		raw := hex.decode(encoded.replace(' ', ''))!
		unmarshal(raw) or {
			assert err is DecodeError
			continue
		}
		assert false, 'expected ${name} to be rejected'
	}
}

fn test_unmarshal_enforces_packet_limit() {
	pli := PictureLossIndication{}
	mut packets := []Packet{}
	for _ in 0 .. 10 {
		packets << Packet(pli)
	}
	raw := marshal(packets)!
	unmarshal(raw, max_packets: 5) or {
		assert err is DecodeError
		unmarshal(raw)!
		return
	}
	assert false, 'the packet count limit must be enforced'
}

fn test_unmarshal_enforces_size_limit() {
	sr := SenderReport{}
	raw := sr.marshal()!
	unmarshal(raw, max_size: 4) or {
		assert err is DecodeError
		return
	}
	assert false, 'the datagram size limit must be enforced'
}

fn test_is_rtcp_demultiplexing() {
	sr := SenderReport{}
	assert is_rtcp(sr.marshal()!)

	// An RTP packet with payload type 96 is in the shared first-byte range but
	// its second byte falls outside the RTCP packet type range.
	assert !is_rtcp([u8(0x80), 0x60, 0x00, 0x01])
	// Payload types 64-95 are reserved by RFC 5761 exactly so this test is
	// decidable.
	assert !is_rtcp([u8(0x80), 0x5F, 0x00, 0x01])
	assert !is_rtcp([u8(0x00), 0xC8, 0x00, 0x01])
	assert !is_rtcp([u8(0x80)])
}

fn test_unmarshal_survives_arbitrary_input() {
	mut seed := u32(0xBEEF)
	for _ in 0 .. 5000 {
		seed = seed * 1103515245 + 12345
		length := 4 + int(seed >> 27) * 4
		mut raw := []u8{len: length}
		for i in 0 .. length {
			seed = seed * 1103515245 + 12345
			raw[i] = u8(seed >> 24)
		}
		raw[0] = (raw[0] & 0x3F) | 0x80
		// Make the declared length agree with the buffer often enough that the
		// body parsers actually get exercised.
		words := length / 4 - 1
		raw[2] = u8(words >> 8)
		raw[3] = u8(words)

		packets := unmarshal(raw) or { continue }
		for packet in packets {
			packet.destination_ssrc()
			packet.marshal() or { continue }
		}
	}
}
