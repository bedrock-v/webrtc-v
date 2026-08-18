// How fast a data channel actually goes, over real sockets.
//
// Run with: make bench    (or: v -prod run examples/throughput)
//
// Build this one with -prod. V's default build is unoptimised, and the whole
// stack is CPU-bound on AES, so a debug build measures the compiler rather than
// the code - by roughly a factor of three.
module main

import time
import webrtc
import webrtc.logging

const message_size = 16 * 1024

const message_count = 512