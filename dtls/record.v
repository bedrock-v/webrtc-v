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

// is_dtls reports whether a datagram plausibly holds a DTLS record.
//
// This is the RFC 7983 demultiplexing test: on a WebRTC socket the same port
// carries STUN, DTLS, RTP and RTCP, and DTLS is the first-byte range 20 to 63.
pub fn is_dtls(b []u8) bool {
	if b.len < record_header_size {
		return false
	}
	return b[0] >= 20 && b[0] <= 63
}

// unmarshal_records decodes every record in a datagram.
//
// A single datagram may carry several records, and RFC 6347 section 4.1.1
// requires a receiver to process all of them. It also requires that a record
// which cannot be parsed causes the rest of the datagram to be discarded rather
// than resynchronised: there is no framing to resynchronise to.
pub fn unmarshal_records(data []u8) ![]Record {
	mut out := []Record{}
	mut r := codec.Reader.new(data)

	for r.remaining() > 0 {
		if r.remaining() < record_header_size {
			return RecordError{
				reason: .too_short
				detail: '${r.remaining()} trailing bytes are not a record header'
			}
		}
		raw_type := r.u8('content type')!
		content_type := content_type_from_value(raw_type) or {
			return RecordError{
				reason: .bad_content_type
				detail: 'content type ${raw_type} is not defined'
			}
		}
		raw_version := r.u16('version')!
		version := protocol_version_from_value(raw_version) or {
			return RecordError{
				reason: .bad_version
				detail: 'version 0x${raw_version.hex()} is not DTLS 1.0 or 1.2'
			}
		}
		epoch := r.u16('epoch')!
		sequence_number := r.u48('sequence number')!
		length := int(r.u16('length')!)
		if length > max_record_payload {
			return RecordError{
				reason: .bad_length
				detail: 'fragment of ${length} bytes exceeds the ${max_record_payload}-byte maximum'
			}
		}
		fragment := r.bytes(length, 'fragment') or {
			return RecordError{
				reason: .bad_length
				detail: 'record declares ${length} bytes but only ${r.remaining()} remain'
			}
		}

		out << Record{
			content_type:    content_type
			version:         version
			epoch:           epoch
			sequence_number: sequence_number
			fragment:        fragment
		}
	}
	return out
}

// AntiReplay rejects a record whose sequence number has already been accepted.
//
// This is the sliding window of RFC 6347 section 4.1.2.6, and the same
// construction as the SRTP one: a bitmask covering the window below the highest
// sequence number seen. Checking and accepting are separate operations, because
// a record must not consume a sequence number until it has been authenticated -
// otherwise an attacker could punch holes in the window with forged records.
pub struct AntiReplay {
mut:
	window_size u64
	highest     u64
	mask        u64
	seen        bool
}

// default_replay_window is the number of records behind the highest accepted
// one that are still acceptable.
pub const default_replay_window = 64