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

// protect_rtp encrypts and authenticates an RTP packet.
pub fn (mut c Context) protect_rtp(packet []u8) ![]u8 {
	header_len := rtp.header_length(packet) or {
		return ProtectionError{
			reason: .bad_input
			detail: err.msg()
		}
	}
	ssrc := read_u32(packet, 8)
	sequence := read_u16(packet, 2)

	mut state := c.srtp[ssrc] or {
		SrtpState{
			replay: ReplayDetector.new(c.options.replay_window)
		}
	}
	// The sender owns the sequence numbering, so the roll-over count advances
	// exactly when the sequence number wraps.
	if !state.started {
		state.started = true
		state.highest_seq = sequence
	} else if sequence < state.highest_seq && u16(state.highest_seq - sequence) > 0x8000 {
		state.roll_over_count++
		state.highest_seq = sequence
	} else if rtp.is_newer_sequence(sequence, state.highest_seq) {
		state.highest_seq = sequence
	}
	roc := state.roll_over_count
	c.srtp[ssrc] = state

	index := (u64(roc) << 16) | u64(sequence)
	header := packet[..header_len]
	payload := packet[header_len..]

	if c.profile.is_aead() {
		nonce := gcm_nonce(c.keys.rtp_salt, ssrc, index)
		sealed := c.rtp_gcm.seal(payload, nonce, header) or {
			return ProtectionError{
				reason: .crypto_failed
				detail: err.msg()
			}
		}
		mut out := []u8{cap: header.len + sealed.len}
		out << header
		out << sealed
		return out
	}

	iv := counter_mode_iv(c.keys.rtp_salt, ssrc, index)
	encrypted := c.apply_keystream(c.keys.rtp_key, iv, payload)!

	mut out := []u8{cap: packet.len + c.profile.rtp_auth_tag_len()}
	out << header
	out << encrypted
	out << c.rtp_auth_tag(out, roc)
	return out
}

// unprotect_rtp verifies and decrypts an SRTP packet.
//
// Authentication is checked before the packet is decrypted and before the
// replay window is advanced, so a forged packet changes no state and reveals
// nothing beyond the fact that it was rejected.
pub fn (mut c Context) unprotect_rtp(packet []u8) ![]u8 {
	tag_len := c.profile.rtp_auth_tag_len()
	header_len := rtp.header_length(packet) or {
		return ProtectionError{
			reason: .bad_input
			detail: err.msg()
		}
	}
	if packet.len < header_len + tag_len {
		return ProtectionError{
			reason: .bad_input
			detail: 'packet of ${packet.len} bytes has no room for a ${tag_len}-byte tag after a ${header_len}-byte header'
		}
	}

	ssrc := read_u32(packet, 8)
	sequence := read_u16(packet, 2)
	mut state := c.srtp[ssrc] or {
		SrtpState{
			replay: ReplayDetector.new(c.options.replay_window)
		}
	}

	// The index is estimated from the roll-over count and the highest sequence
	// number seen, so that a packet reordered across a wrap is still decrypted
	// against the counter its sender used.
	roc, index := if state.started {
		rtp.unwrap_sequence(state.roll_over_count, state.highest_seq, sequence)
	} else {
		u32(0), u64(sequence)
	}

	if !state.replay.check(index) {
		return ProtectionError{
			reason: .replayed
			detail: 'packet index ${index} has already been seen or is outside the replay window'
		}
	}

	header := packet[..header_len]
	mut plaintext := []u8{}

	if c.profile.is_aead() {
		nonce := gcm_nonce(c.keys.rtp_salt, ssrc, index)
		plaintext = c.rtp_gcm.open(packet[header_len..], nonce, header) or {
			return ProtectionError{
				reason: .auth_failed
				detail: 'AEAD tag did not verify'
			}
		}
	} else {
		body := packet[..packet.len - tag_len]
		received_tag := packet[packet.len - tag_len..]
		expected := c.rtp_auth_tag(body, roc)
		if !hmac.equal(expected, received_tag) {
			return ProtectionError{
				reason: .auth_failed
				detail: 'HMAC did not verify'
			}
		}
		iv := counter_mode_iv(c.keys.rtp_salt, ssrc, index)
		plaintext = c.apply_keystream(c.keys.rtp_key, iv, body[header_len..])!
	}

	// Only now, with the packet proven authentic, is any state advanced.
	state.replay.accept(index)
	if !state.started {
		// The first packet establishes the watermark. It cannot go through the
		// comparison below: the initial highest_seq is zero, and RFC 3550
		// requires senders to start from a random sequence number, so half of
		// all streams would begin with a value that compares as older than the
		// sentinel and never advance it.
		state.started = true
		state.roll_over_count = roc
		state.highest_seq = sequence
	} else if roc > state.roll_over_count
		|| (roc == state.roll_over_count && rtp.is_newer_sequence(sequence, state.highest_seq)) {
		state.roll_over_count = roc
		state.highest_seq = sequence
	}
	c.srtp[ssrc] = state

	mut out := []u8{cap: header.len + plaintext.len}
	out << header
	out << plaintext
	return out
}

// protect_rtcp encrypts and authenticates an RTCP packet.
pub fn (mut c Context) protect_rtcp(packet []u8) ![]u8 {
	if packet.len < srtcp_header_size {
		return ProtectionError{
			reason: .bad_input
			detail: 'RTCP packet of ${packet.len} bytes is shorter than the ${srtcp_header_size}-byte header'
		}
	}
	ssrc := read_u32(packet, 4)
	mut state := c.srtcp[ssrc] or {
		SrtcpState{
			replay: ReplayDetector.new(c.options.replay_window)
		}
	}
	if state.index >= max_srtcp_index {
		return ProtectionError{
			reason: .key_exhausted
			detail: 'the 31-bit SRTCP index for source ${ssrc} is exhausted; the master key must be replaced'
		}
	}
	state.index++
	index := state.index
	c.srtcp[ssrc] = state

	header := packet[..srtcp_header_size]
	payload := packet[srtcp_header_size..]
	// The high bit of the index field marks the packet as encrypted.
	index_field := [u8((index >> 24) | 0x80), u8(index >> 16), u8(index >> 8), u8(index)]

	if c.profile.is_aead() {
		mut aad := []u8{cap: srtcp_header_size + srtcp_index_size}
		aad << header
		aad << index_field
		nonce := gcm_nonce(c.keys.rtcp_salt, ssrc, u64(index))
		sealed := c.rtcp_gcm.seal(payload, nonce, aad) or {
			return ProtectionError{
				reason: .crypto_failed
				detail: err.msg()
			}
		}
		mut out := []u8{cap: header.len + sealed.len + srtcp_index_size}
		out << header
		out << sealed
		out << index_field
		return out
	}

	iv := counter_mode_iv(c.keys.rtcp_salt, ssrc, u64(index))
	encrypted := c.apply_keystream(c.keys.rtcp_key, iv, payload)!

	mut out := []u8{cap: packet.len + srtcp_index_size + c.profile.rtcp_auth_tag_len()}
	out << header
	out << encrypted
	out << index_field
	out << c.rtcp_auth_tag(out)
	return out
}