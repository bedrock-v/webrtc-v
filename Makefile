V ?= v
# The root `webrtc` module is not listed: V 0.5.2 mis-parses `-shared -check .`
# for a module in the current directory. It is type-checked by `make examples`,
# which builds examples/peer-connection against it.
MODULES := netaddr logging transport internal/codec internal/aes internal/randutil \
           stun stunclient turn mdns sdp rtp rtcp srtp ice dtls sctp datachannel
# The modules that decode input from the network, and so get the extra passes.
CODECS  := internal/codec internal/aes netaddr stun sdp rtp rtcp srtp sctp turn mdns
EXAMPLES := $(notdir $(patsubst %/,%,$(wildcard examples/*/)))
