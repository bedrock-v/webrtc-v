module srtp

import webrtc.internal.aes
import crypto.hmac
import crypto.sha1
import webrtc.rtp

// srtcp_header_size is the part of an RTCP packet that is never encrypted: the
// common header and the sender's synchronisation source.
const srtcp_header_size = 8

// srtcp_index_size is the size of the trailing E-flag and index field.
const srtcp_index_size = 4

// max_srtcp_index is the largest value the 31-bit SRTCP index can hold. Once it
// is reached the master key must be replaced; continuing would repeat a counter
// block and destroy confidentiality.
const max_srtcp_index = u32(0x7FFFFFFF)

// ProtectionError is returned when a packet cannot be protected or unprotected.
pub struct ProtectionError {
pub:
	reason Reason
	detail string
}

pub enum Reason {
	// bad_input: the packet is malformed before any cryptography is attempted.
	bad_input
	// auth_failed: the authentication tag did not verify. The packet was
	// forged, corrupted, or protected with a different key.
	auth_failed
	// replayed: the packet index has already been accepted, or is too old to
	// judge.
	replayed
	// key_exhausted: the packet index space for this key is used up.
	key_exhausted
	// crypto_failed: an underlying primitive refused the input.
	crypto_failed
}

pub fn (e ProtectionError) msg() string {
	return 'srtp: ${e.reason}: ${e.detail}'
}

pub fn (e ProtectionError) code() int {
	return int(e.reason) + 1
}

// srtp_state is the per-source state an SRTP stream needs.
struct SrtpState {
mut:
	// roll_over_count extends the 16-bit sequence number to the 48-bit packet
	// index the ciphers are keyed on.
	roll_over_count u32
	highest_seq     u16
	started         bool
	replay          ReplayDetector
}

// srtcp_state is the per-source state an SRTCP stream needs. SRTCP carries its
// own 31-bit index in the packet, so there is no roll-over count to track.
struct SrtcpState {
mut:
	index  u32
	replay ReplayDetector
}

// Options tunes a context.
@[params]
pub struct Options {
pub:
	replay_window int = default_replay_window
}

// Context protects and unprotects packets for one direction of one transport.
//
// Two contexts are needed per connection: one keyed with the local write key
// for outbound packets, one with the peer's for inbound. Sharing a context
// between directions would make both sides generate the same keystream for the
// same index, which is a complete break.
//
// A Context is not safe for concurrent use. Each one belongs to a single
// transport, and a transport processes packets in order on one thread.
pub struct Context {
mut:
	profile Profile
	keys    SessionKeys
	// rtp_gcm and rtcp_gcm are built once. The key schedule and the GHASH table
	// cost about as much as encrypting a small packet, so building them per
	// packet halves throughput on exactly the path that carries media.
	rtp_gcm  &aes.Gcm = unsafe { nil }
	rtcp_gcm &aes.Gcm = unsafe { nil }
	options  Options
	srtp     map[u32]SrtpState
	srtcp    map[u32]SrtcpState
}

// Context.new derives session keys from a master key and salt.
pub fn Context.new(master_key []u8, master_salt []u8, profile Profile, options Options) !&Context {
	keys := derive_session_keys(master_key, master_salt, profile)!
	mut context := &Context{
		profile: profile
		keys:    keys
		options: options
	}
	if profile.is_aead() {
		context.rtp_gcm = aes.Gcm.new(keys.rtp_key)!
		context.rtcp_gcm = aes.Gcm.new(keys.rtcp_key)!
	}
	return context
}

// Context.from_keying_material builds a context from one half of the DTLS-SRTP
// extractor output.
pub fn Context.from_keying_material(material KeyingMaterial, profile Profile, options Options) !&Context {
	return Context.new(material.key, material.salt, profile, options)!
}

// profile returns the protection profile in use.
@[inline]
pub fn (c &Context) profile() Profile {
	return c.profile
}