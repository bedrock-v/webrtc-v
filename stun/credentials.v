module stun

import crypto.md5

// Credentials derive the HMAC key used by MESSAGE-INTEGRITY.
//
// Two mechanisms exist. ICE uses short-term credentials, where the key is the
// password itself and both sides learn it out of band through the signalling
// channel. TURN uses long-term credentials, where the key is a digest binding
// the username, realm and password together so that the password is not usable
// against a different realm.

// short_term_key returns the MESSAGE-INTEGRITY key for short-term credentials
// (RFC 8489 section 9.1.1): the SASLprep-processed password.
//
// ICE passwords are drawn from ice-char, which is a subset of ASCII, and
// SASLprep is the identity map over that set. Passwords outside it are rejected
// rather than passed through unnormalised, because two peers that normalise
// differently would compute different keys and fail authentication with no
// diagnosable cause.
pub fn short_term_key(password string) ![]u8 {
	if password == '' {
		return error('stun: empty short-term password')
	}
	for c in password.bytes() {
		// SASLprep prohibits control characters outright and maps the various
		// Unicode spaces onto U+0020; over printable ASCII, including the space
		// itself, it is the identity.
		if c < 0x20 || c > 0x7E {
			return error('stun: short-term password contains a character outside printable ASCII, which this implementation does not SASLprep')
		}
	}
	return password.bytes()
}