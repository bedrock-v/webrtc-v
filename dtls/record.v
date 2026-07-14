module dtls

import webrtc.internal.codec

// The DTLS record layer (RFC 6347 section 4.1).
//
// DTLS differs from TLS here in the two fields that make it work over a
// datagram transport: an explicit sequence number, because records can be
// reordered or lost, and an epoch, which counts how many times the keys have
// changed. Together they identify a record uniquely, which is what lets the
// replay window below reject a captured record without any per-connection
// state beyond a bitmask.

// record_header_size is the fixed 13-byte header.
pub const record_header_size = 13

// max_record_payload is the largest fragment a record may carry (RFC 6347
// section 4.1). Nothing in WebRTC approaches it; the limit exists so a hostile
// length field cannot choose our allocation size.
pub const max_record_payload = 16384

// ContentType identifies what a record carries.
pub enum ContentType as u8 {
	change_cipher_spec = 20
	alert              = 21
	handshake          = 22
	application_data   = 23
}

pub fn (c ContentType) str() string {
	return match c {
		.change_cipher_spec { 'change_cipher_spec' }
		.alert { 'alert' }
		.handshake { 'handshake' }
		.application_data { 'application_data' }
	}
}

fn content_type_from_value(v u8) ?ContentType {
	return match v {
		20 { ContentType.change_cipher_spec }
		21 { ContentType.alert }
		22 { ContentType.handshake }
		23 { ContentType.application_data }
		else { none }
	}
}

// ProtocolVersion is the DTLS version, encoded as the ones' complement of the
// TLS version it corresponds to. DTLS 1.2 is 0xFEFD, which is "TLS 1.2"
// inverted, and the ordering is therefore reversed: a numerically smaller value
// is a newer version.
pub enum ProtocolVersion as u16 {
	dtls_1_0 = 0xFEFF
	dtls_1_2 = 0xFEFD
}

pub fn (v ProtocolVersion) str() string {
	return match v {
		.dtls_1_0 { 'DTLS 1.0' }
		.dtls_1_2 { 'DTLS 1.2' }
	}
}

fn protocol_version_from_value(v u16) ?ProtocolVersion {
	return match v {
		0xFEFF { ProtocolVersion.dtls_1_0 }
		0xFEFD { ProtocolVersion.dtls_1_2 }
		else { none }
	}
}