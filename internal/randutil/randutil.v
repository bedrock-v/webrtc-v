module randutil

import crypto.rand

// Every identifier in the WebRTC stack that an attacker must not be able to
// guess - ICE credentials, STUN transaction IDs, DTLS randoms, SSRCs - is
// generated here, from the operating system CSPRNG. There is deliberately no
// math/rand fallback: a failure to read entropy is returned as an error rather
// than silently downgraded to a predictable source.

// Character sets from RFC 8839 section 5.4: ICE credentials are drawn from
// ice-char, which is ALPHA / DIGIT / '+' / '/'.
const ice_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.bytes()