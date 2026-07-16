module dtls

import webrtc.internal.codec
import webrtc.internal.randutil

// The DTLS handshake protocol (RFC 6347 section 4.2, on top of RFC 5246
// section 7.4).
//
// A handshake message carries three fields TLS does not have: a message
// sequence number, and a fragment offset and length. Together they let one
// logical message be split across several records, which is what makes a
// certificate larger than the path MTU deliverable over UDP.

// handshake_header_size is the fixed 12-byte header.
pub const handshake_header_size = 12

// max_handshake_body bounds one reassembled message. A certificate is the
// largest thing that crosses this layer and is a few hundred bytes; the limit
// is what stops a peer from declaring a 16 MiB message and making us hold a
// buffer for it.
pub const max_handshake_body = 65536

// random_size is the size of a hello random: four bytes of time and 28 random.
pub const random_size = 32

// max_cookie_size is the RFC 6347 limit on a HelloVerifyRequest cookie.
pub const max_cookie_size = 255

// HandshakeType identifies a handshake message.
pub enum HandshakeType as u8 {
	hello_request        = 0
	client_hello         = 1
	server_hello         = 2
	hello_verify_request = 3
	certificate          = 11
	server_key_exchange  = 12
	certificate_request  = 13
	server_hello_done    = 14
	certificate_verify   = 15
	client_key_exchange  = 16
	finished             = 20
}

pub fn (t HandshakeType) str() string {
	return match t {
		.hello_request { 'HelloRequest' }
		.client_hello { 'ClientHello' }
		.server_hello { 'ServerHello' }
		.hello_verify_request { 'HelloVerifyRequest' }
		.certificate { 'Certificate' }
		.server_key_exchange { 'ServerKeyExchange' }
		.certificate_request { 'CertificateRequest' }
		.server_hello_done { 'ServerHelloDone' }
		.certificate_verify { 'CertificateVerify' }
		.client_key_exchange { 'ClientKeyExchange' }
		.finished { 'Finished' }
	}
}

fn handshake_type_from_value(v u8) ?HandshakeType {
	return match v {
		0 { HandshakeType.hello_request }
		1 { HandshakeType.client_hello }
		2 { HandshakeType.server_hello }
		3 { HandshakeType.hello_verify_request }
		11 { HandshakeType.certificate }
		12 { HandshakeType.server_key_exchange }
		13 { HandshakeType.certificate_request }
		14 { HandshakeType.server_hello_done }
		15 { HandshakeType.certificate_verify }
		16 { HandshakeType.client_key_exchange }
		20 { HandshakeType.finished }
		else { none }
	}
}

// CipherSuite is a TLS cipher suite identifier.
pub enum CipherSuite as u16 {
	// The suite browsers negotiate, and the only one this implementation
	// offers. ECDHE gives forward secrecy, ECDSA matches the P-256 certificate
	// we generate, and GCM authenticates and encrypts in one pass.
	ecdhe_ecdsa_with_aes_128_gcm_sha256 = 0xC02B
}

pub fn (c CipherSuite) str() string {
	return match c {
		.ecdhe_ecdsa_with_aes_128_gcm_sha256 { 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256' }
	}
}

fn cipher_suite_from_value(v u16) ?CipherSuite {
	return match v {
		0xC02B { CipherSuite.ecdhe_ecdsa_with_aes_128_gcm_sha256 }
		else { none }
	}
}

// HandshakeError describes a handshake message that cannot be built or parsed.
pub struct HandshakeError {
pub:
	detail string
}

pub fn (e HandshakeError) msg() string {
	return 'dtls: handshake: ${e.detail}'
}

pub fn (e HandshakeError) code() int {
	return 20
}

// HandshakeHeader is the per-fragment header.
pub struct HandshakeHeader {
pub mut:
	typ HandshakeType
	// length is the size of the whole reassembled message, not of this
	// fragment.
	length u32
	// message_seq numbers logical messages, so a retransmission is recognisable
	// and so out-of-order delivery can be reordered.
	message_seq     u16
	fragment_offset u32
	fragment_length u32
}

// is_complete reports whether this fragment is the whole message.
@[inline]
pub fn (h &HandshakeHeader) is_complete() bool {
	return h.fragment_offset == 0 && h.fragment_length == h.length
}

fn (h &HandshakeHeader) marshal_into(mut w codec.Writer) {
	w.u8(u8(h.typ))
	w.u24(h.length)
	w.u16(h.message_seq)
	w.u24(h.fragment_offset)
	w.u24(h.fragment_length)
}