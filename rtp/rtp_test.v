module rtp

import encoding.hex

// A minimal packet: version 2, no padding, no extension, no CSRC, payload type
// 96, sequence 27035, timestamp 0xd9c8dd1a, SSRC 0x1c64b0d4, four payload bytes.
const minimal_packet = '8060699b' + 'd9c8dd1a' + '1c64b0d4' + '98364323'