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