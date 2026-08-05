module sctp

import time

// Sending and receiving user data: fragmentation, acknowledgement,
// retransmission, congestion control and reassembly.

// fast_retransmit_threshold is how many acknowledgements must report a TSN
// missing before it is resent without waiting for the timer
// (RFC 4960 section 7.2.4). Three is the value TCP uses and for the same
// reason: fewer would make reordering look like loss.
const fast_retransmit_threshold = 3