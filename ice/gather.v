module ice

import net
import time
import webrtc.netaddr
import webrtc.stun
import webrtc.transport

// gather_timeout bounds one server-reflexive lookup. Gathering blocks the
// caller, so a STUN server that is down must not hold up the whole session; the
// host candidates are already usable by then.
const gather_timeout = time.Duration(2 * time.second)