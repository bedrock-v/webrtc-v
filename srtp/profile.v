// Package srtp implements the Secure Real-time Transport Protocol (RFC 3711)
// and its AES-GCM profiles (RFC 7714).
//
// SRTP is what makes WebRTC media confidential and authentic. The keys come
// from the DTLS handshake through the extractor of RFC 5764, so this package
// never negotiates anything: it takes keying material and turns RTP into SRTP
// and back.
//
// Two rules govern everything here. Authentication is verified before anything
// else is done with a packet, so a forged packet cannot reach the replay window
// or the decoder. And a packet that fails any check is dropped with an error
// rather than passed on partially processed.
module srtp