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

// HandshakeFragment is a header plus the bytes it covers.
pub struct HandshakeFragment {
pub mut:
	header HandshakeHeader
	body   []u8
}

// unmarshal_handshake_fragments decodes every fragment in a record payload.
//
// One record can carry several handshake messages, which is how a server packs
// ServerHello, Certificate, ServerKeyExchange and ServerHelloDone into a single
// flight.
pub fn unmarshal_handshake_fragments(data []u8) ![]HandshakeFragment {
	mut out := []HandshakeFragment{}
	mut r := codec.Reader.new(data)

	for r.remaining() > 0 {
		if r.remaining() < handshake_header_size {
			return HandshakeError{
				detail: '${r.remaining()} trailing bytes are not a handshake header'
			}
		}
		raw_type := r.u8('handshake type')!
		typ := handshake_type_from_value(raw_type) or {
			return HandshakeError{
				detail: 'handshake type ${raw_type} is not defined'
			}
		}
		length := r.u24('length')!
		message_seq := r.u16('message sequence')!
		fragment_offset := r.u24('fragment offset')!
		fragment_length := r.u24('fragment length')!

		if length > max_handshake_body {
			return HandshakeError{
				detail: '${typ} declares ${length} bytes, over the ${max_handshake_body}-byte limit'
			}
		}
		if u64(fragment_offset) + u64(fragment_length) > u64(length) {
			return HandshakeError{
				detail: '${typ} fragment at ${fragment_offset} of ${fragment_length} bytes runs past the ${length}-byte message'
			}
		}
		body := r.bytes(int(fragment_length), 'fragment body') or {
			return HandshakeError{
				detail: '${typ} fragment declares ${fragment_length} bytes but only ${r.remaining()} remain'
			}
		}

		out << HandshakeFragment{
			header: HandshakeHeader{
				typ:             typ
				length:          length
				message_seq:     message_seq
				fragment_offset: fragment_offset
				fragment_length: fragment_length
			}
			body:   body
		}
	}
	return out
}

// fragment_message splits a complete handshake message into fragments that fit
// max_fragment bytes of record payload each.
//
// Fragmenting at this layer rather than relying on IP fragmentation is what
// keeps a handshake working across a path that drops fragmented datagrams,
// which many do.
pub fn fragment_message(typ HandshakeType, message_seq u16, body []u8, max_fragment int) ![][]u8 {
	if body.len > max_handshake_body {
		return HandshakeError{
			detail: '${typ} body of ${body.len} bytes exceeds the ${max_handshake_body}-byte limit'
		}
	}
	payload_limit := max_fragment - handshake_header_size
	if payload_limit < 1 {
		return HandshakeError{
			detail: 'a fragment limit of ${max_fragment} bytes leaves no room for the handshake header'
		}
	}

	mut out := [][]u8{}
	mut offset := 0
	for {
		mut chunk := body.len - offset
		if chunk > payload_limit {
			chunk = payload_limit
		}
		header := HandshakeHeader{
			typ:             typ
			length:          u32(body.len)
			message_seq:     message_seq
			fragment_offset: u32(offset)
			fragment_length: u32(chunk)
		}
		mut w := codec.Writer.with_capacity(handshake_header_size + chunk)
		header.marshal_into(mut w)
		w.bytes(body[offset..offset + chunk])
		out << w.buf

		offset += chunk
		// A zero-length message still needs exactly one fragment.
		if offset >= body.len {
			break
		}
	}
	return out
}

// Random is a hello random: 32 bytes, conventionally four of timestamp and 28
// of entropy.
pub struct Random {
pub:
	bytes []u8
}

// Random.generate returns a fresh hello random.
//
// RFC 5246 puts a timestamp in the first four bytes. That leaks the sender's
// clock, and TLS 1.3 removed it for that reason; since nothing verifies it,
// this implementation fills all 32 bytes from the CSPRNG.
pub fn Random.generate() !Random {
	return Random{
		bytes: randutil.bytes(random_size)!
	}
}

// ClientHello is the first message of a handshake.
pub struct ClientHello {
pub mut:
	version    ProtocolVersion = .dtls_1_2
	random     Random
	session_id []u8
	// cookie is empty in the first ClientHello and echoes the server's
	// HelloVerifyRequest in the second.
	cookie              []u8
	cipher_suites       []CipherSuite
	compression_methods []u8 = [u8(0)]
	extensions          []Extension
}

// ServerHello selects the parameters for the connection.
pub struct ServerHello {
pub mut:
	version            ProtocolVersion = .dtls_1_2
	random             Random
	session_id         []u8
	cipher_suite       CipherSuite
	compression_method u8
	extensions         []Extension
}

// HelloVerifyRequest carries the stateless cookie that proves the client can
// receive at the address it claims.
//
// This is DTLS's answer to being a datagram protocol: without it, a single
// spoofed ClientHello would make a server allocate state and send a much larger
// flight to a forged address, which is an amplification attack.
pub struct HelloVerifyRequest {
pub mut:
	// The version here is DTLS 1.0 by convention, even for a 1.2 handshake;
	// RFC 6347 section 4.2.1 keeps it that way for backward compatibility.
	version ProtocolVersion = .dtls_1_0
	cookie  []u8
}

// CertificateMessage carries the sender's certificate chain. WebRTC endpoints
// send exactly one self-signed certificate.
pub struct CertificateMessage {
pub mut:
	certificates [][]u8
}

// ServerKeyExchange carries the server's ephemeral ECDH public key and a
// signature over it.
//
// The signature is what binds the ephemeral key to the certificate: without it,
// anyone on the path could substitute their own key. It covers the two randoms
// as well, so it cannot be replayed into a different handshake.
pub struct ServerKeyExchange {
pub mut:
	curve          NamedCurve = .secp256r1
	public_key     []u8
	signature_hash HashAlgorithmId      = .sha256
	signature_type SignatureAlgorithmId = .ecdsa
	signature      []u8
}

// ClientKeyExchange carries the client's ephemeral ECDH public key.
pub struct ClientKeyExchange {
pub mut:
	public_key []u8
}

// CertificateVerify proves the sender holds the private key for the certificate
// it sent, by signing the handshake transcript.
pub struct CertificateVerify {
pub mut:
	signature_hash HashAlgorithmId      = .sha256
	signature_type SignatureAlgorithmId = .ecdsa
	signature      []u8
}

// Finished carries the verify data over the whole transcript.
pub struct Finished {
pub mut:
	verify_data []u8
}

// ServerHelloDone marks the end of the server's first flight.
pub struct ServerHelloDone {}

// ClientCertificateType names a kind of certificate a server will accept.
pub enum ClientCertificateType as u8 {
	rsa_sign   = 1
	ecdsa_sign = 64
}

// CertificateRequest asks the client for a certificate.
//
// WebRTC always authenticates both ends: each side has a fingerprint for the
// other from the SDP, and a fingerprint is only worth checking if the peer had
// to prove it holds the matching key. A server that omitted this message would
// have nothing to check.
pub struct CertificateRequest {
pub mut:
	certificate_types []ClientCertificateType = [ClientCertificateType.ecdsa_sign]
	signature_schemes []SignatureScheme       = [ecdsa_sha256]
	// certificate_authorities is always empty here: there is no CA, so there is
	// no list of acceptable issuers to send.
	certificate_authorities [][]u8
}

// HandshakeMessage is any handshake message.
pub type HandshakeMessage = CertificateMessage
	| CertificateRequest
	| CertificateVerify
	| ClientHello
	| ClientKeyExchange
	| Finished
	| HelloVerifyRequest
	| ServerHello
	| ServerHelloDone
	| ServerKeyExchange

// handshake_type returns the wire type of a message.
pub fn (m HandshakeMessage) handshake_type() HandshakeType {
	return match m {
		ClientHello { HandshakeType.client_hello }
		ServerHello { HandshakeType.server_hello }
		HelloVerifyRequest { HandshakeType.hello_verify_request }
		CertificateMessage { HandshakeType.certificate }
		ServerKeyExchange { HandshakeType.server_key_exchange }
		CertificateRequest { HandshakeType.certificate_request }
		ServerHelloDone { HandshakeType.server_hello_done }
		CertificateVerify { HandshakeType.certificate_verify }
		ClientKeyExchange { HandshakeType.client_key_exchange }
		Finished { HandshakeType.finished }
	}
}

// marshal serialises the message body, without the handshake header.
pub fn (m HandshakeMessage) marshal() ![]u8 {
	match m {
		ClientHello { return marshal_client_hello(m)! }
		ServerHello { return marshal_server_hello(m)! }
		HelloVerifyRequest { return marshal_hello_verify_request(m)! }
		CertificateMessage { return marshal_certificate(m)! }
		ServerKeyExchange { return marshal_server_key_exchange(m)! }
		CertificateRequest { return marshal_certificate_request(m)! }
		ServerHelloDone { return []u8{} }
		CertificateVerify { return marshal_certificate_verify(m)! }
		ClientKeyExchange { return marshal_client_key_exchange(m)! }
		Finished { return m.verify_data.clone() }
	}
}

fn marshal_client_hello(m ClientHello) ![]u8 {
	if m.random.bytes.len != random_size {
		return HandshakeError{
			detail: 'ClientHello random is ${m.random.bytes.len} bytes, expected ${random_size}'
		}
	}
	if m.session_id.len > 32 {
		return HandshakeError{
			detail: 'session id of ${m.session_id.len} bytes exceeds 32'
		}
	}
	if m.cookie.len > max_cookie_size {
		return HandshakeError{
			detail: 'cookie of ${m.cookie.len} bytes exceeds ${max_cookie_size}'
		}
	}
	if m.cipher_suites.len == 0 {
		return HandshakeError{
			detail: 'ClientHello offers no cipher suites'
		}
	}

	mut w := codec.Writer.new()
	w.u16(u16(m.version))
	w.bytes(m.random.bytes)
	w.u8(u8(m.session_id.len))
	w.bytes(m.session_id)
	w.u8(u8(m.cookie.len))
	w.bytes(m.cookie)
	w.u16(u16(m.cipher_suites.len * 2))
	for suite in m.cipher_suites {
		w.u16(u16(suite))
	}
	w.u8(u8(m.compression_methods.len))
	w.bytes(m.compression_methods)
	w.bytes(marshal_extensions(m.extensions)!)
	return w.buf
}

fn marshal_server_hello(m ServerHello) ![]u8 {
	if m.random.bytes.len != random_size {
		return HandshakeError{
			detail: 'ServerHello random is ${m.random.bytes.len} bytes, expected ${random_size}'
		}
	}
	if m.session_id.len > 32 {
		return HandshakeError{
			detail: 'session id of ${m.session_id.len} bytes exceeds 32'
		}
	}
	mut w := codec.Writer.new()
	w.u16(u16(m.version))
	w.bytes(m.random.bytes)
	w.u8(u8(m.session_id.len))
	w.bytes(m.session_id)
	w.u16(u16(m.cipher_suite))
	w.u8(m.compression_method)
	w.bytes(marshal_extensions(m.extensions)!)
	return w.buf
}

fn marshal_hello_verify_request(m HelloVerifyRequest) ![]u8 {
	if m.cookie.len > max_cookie_size {
		return HandshakeError{
			detail: 'cookie of ${m.cookie.len} bytes exceeds ${max_cookie_size}'
		}
	}
	mut w := codec.Writer.new()
	w.u16(u16(m.version))
	w.u8(u8(m.cookie.len))
	w.bytes(m.cookie)
	return w.buf
}

fn marshal_certificate(m CertificateMessage) ![]u8 {
	mut body := codec.Writer.new()
	for certificate in m.certificates {
		if certificate.len > 0xFFFFFF {
			return HandshakeError{
				detail: 'certificate of ${certificate.len} bytes exceeds the 24-bit length field'
			}
		}
		body.u24(u32(certificate.len))
		body.bytes(certificate)
	}
	if body.len() > 0xFFFFFF {
		return HandshakeError{
			detail: 'certificate chain of ${body.len()} bytes exceeds the 24-bit length field'
		}
	}
	mut w := codec.Writer.with_capacity(3 + body.len())
	w.u24(u32(body.len()))
	w.bytes(body.buf)
	return w.buf
}

fn marshal_server_key_exchange(m ServerKeyExchange) ![]u8 {
	if m.public_key.len == 0 || m.public_key.len > 255 {
		return HandshakeError{
			detail: 'ECDH public key is ${m.public_key.len} bytes, outside the 1-255 range'
		}
	}
	if m.signature.len > 0xFFFF {
		return HandshakeError{
			detail: 'signature of ${m.signature.len} bytes exceeds the 16-bit length field'
		}
	}
	mut w := codec.Writer.new()
	w.bytes(server_ecdh_params(m.curve, m.public_key))
	w.u8(u8(m.signature_hash))
	w.u8(u8(m.signature_type))
	w.u16(u16(m.signature.len))
	w.bytes(m.signature)
	return w.buf
}

// server_ecdh_params builds the ServerECDHParams structure, which is both sent
// on the wire and covered by the signature. It is built in one place so the two
// uses cannot drift apart.
pub fn server_ecdh_params(curve NamedCurve, public_key []u8) []u8 {
	mut w := codec.Writer.with_capacity(4 + public_key.len)
	// curve_type: named_curve
	w.u8(3)
	w.u16(u16(curve))
	w.u8(u8(public_key.len))
	w.bytes(public_key)
	return w.buf
}

fn marshal_certificate_request(m CertificateRequest) ![]u8 {
	if m.certificate_types.len == 0 || m.certificate_types.len > 255 {
		return HandshakeError{
			detail: 'CertificateRequest names ${m.certificate_types.len} certificate types, expected 1 to 255'
		}
	}
	mut w := codec.Writer.new()
	w.u8(u8(m.certificate_types.len))
	for typ in m.certificate_types {
		w.u8(u8(typ))
	}
	w.u16(u16(m.signature_schemes.len * 2))
	for scheme in m.signature_schemes {
		w.u8(u8(scheme.hash))
		w.u8(u8(scheme.signature))
	}
	mut authorities := codec.Writer.new()
	for authority in m.certificate_authorities {
		authorities.u16(u16(authority.len))
		authorities.bytes(authority)
	}
	w.u16(u16(authorities.len()))
	w.bytes(authorities.buf)
	return w.buf
}