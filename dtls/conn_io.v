module dtls

import time

// Record input and output for a connection.
//
// Everything the handshake and the application send goes through send_records,
// and everything received goes through receive_records. Keeping both in one
// place is what makes the epoch and sequence-number bookkeeping - the part that
// is fatal to get wrong, because a repeated nonce breaks GCM completely -
// checkable by reading a single file.

// alert_level_fatal and the alert descriptions this implementation sends or
// recognises (RFC 5246 section 7.2).
const alert_level_warning = u8(1)