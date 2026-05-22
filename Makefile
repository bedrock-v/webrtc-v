V ?= v
# The root `webrtc` module is not listed: V 0.5.2 mis-parses `-shared -check .`
# for a module in the current directory. It is type-checked by `make examples`,
# which builds examples/peer-connection against it.
MODULES := netaddr logging transport internal/codec internal/aes internal/randutil \
           stun stunclient turn mdns sdp rtp rtcp srtp ice dtls sctp datachannel
# The modules that decode input from the network, and so get the extra passes.
CODECS  := internal/codec internal/aes netaddr stun sdp rtp rtcp srtp sctp turn mdns
EXAMPLES := $(notdir $(patsubst %/,%,$(wildcard examples/*/)))

.DEFAULT_GOAL := check

.PHONY: help
help:
	@printf '  %-12s %s\n' \
		link       'Link this checkout into V so `import webrtc.x` resolves' \
		check      'fmt-check, vet and test - what CI runs on a pull request' \
		test       'Run the test suite' \
		fmt        'Format in place' \
		fmt-check  'Fail if anything is unformatted' \
		vet        "Run V's vet" \
		build      'Type-check every module' \
		build-prod 'Type-check every module with optimisation on' \
		examples   'Build every example' \
		harden     'Run the decoder tests through three backend code paths' \
		bench      'Measure data channel throughput (optimised build)' \
		docs       'Generate the API documentation into _docs/' \
		clean      'Remove build output'

.PHONY: link
link:
	@mkdir -p "$(HOME)/.vmodules"
	@ln -sfn "$(CURDIR)" "$(HOME)/.vmodules/webrtc"
	@echo "linked $(HOME)/.vmodules/webrtc -> $(CURDIR)"

.PHONY: check
check: fmt-check vet test

.PHONY: test
test:
	$(V) test .

.PHONY: fmt
fmt:
	$(V) fmt -w .

.PHONY: fmt-check
fmt-check:
	$(V) fmt -verify .

.PHONY: vet
vet:
	$(V) vet .

.PHONY: build
build:
	@set -e; for module in $(MODULES); do \
		echo "  check $$module"; \
		$(V) -shared -check "$$module"; \
	done
