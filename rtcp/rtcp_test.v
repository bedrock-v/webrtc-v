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