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

// RecordError describes why a datagram is not a usable DTLS record.
pub struct RecordError {
pub:
	reason RecordErrorReason
	detail string
}

pub enum RecordErrorReason {
	// too_short: fewer bytes than the header requires.
	too_short
	// bad_content_type: a content type outside the four defined values.
	bad_content_type
	// bad_version: a version this implementation does not speak.
	bad_version
	// bad_length: the declared fragment length disagrees with the datagram, or
	// exceeds the maximum.
	bad_length
	// replayed: the sequence number has already been seen in this epoch.
	replayed
	// wrong_epoch: the record belongs to an epoch we have no keys for.
	wrong_epoch
	// decrypt_failed: the record did not authenticate.
	decrypt_failed
}

pub fn (e RecordError) msg() string {
	return 'dtls: record ${e.reason}: ${e.detail}'
}

pub fn (e RecordError) code() int {
	return int(e.reason) + 10
}

// Record is one DTLS record.
pub struct Record {
pub mut:
	content_type ContentType
	version      ProtocolVersion = .dtls_1_2
	epoch        u16
	// sequence_number is 48 bits on the wire.
	sequence_number u64
	// fragment is the record payload: ciphertext when the epoch is protected,
	// plaintext otherwise.
	fragment []u8
}

// marshal serialises a record.
pub fn (r &Record) marshal() ![]u8 {
	if r.fragment.len > max_record_payload {
		return RecordError{
			reason: .bad_length
			detail: 'fragment of ${r.fragment.len} bytes exceeds the ${max_record_payload}-byte maximum'
		}
	}
	if r.sequence_number > 0xFFFFFFFFFFFF {
		return RecordError{
			reason: .bad_length
			detail: 'sequence number ${r.sequence_number} does not fit 48 bits'
		}
	}
	mut w := codec.Writer.with_capacity(record_header_size + r.fragment.len)
	w.u8(u8(r.content_type))
	w.u16(u16(r.version))
	w.u16(r.epoch)
	w.u48(r.sequence_number)
	w.u16(u16(r.fragment.len))
	w.bytes(r.fragment)
	return w.buf
}

// header_bytes returns the 13-byte header on its own.
//
// AEAD record protection needs it as additional authenticated data, and needs
// it before the ciphertext length is known, so it is built separately from
// marshal.
pub fn (r &Record) header_bytes(fragment_length int) []u8 {
	mut w := codec.Writer.with_capacity(record_header_size)
	w.u8(u8(r.content_type))
	w.u16(u16(r.version))
	w.u16(r.epoch)
	w.u48(r.sequence_number)
	w.u16(u16(fragment_length))
	return w.buf
}