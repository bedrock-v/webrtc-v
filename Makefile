V ?= v
# The root `webrtc` module is not listed: V 0.5.2 mis-parses `-shared -check .`
# for a module in the current directory. It is type-checked by `make examples`,
# which builds examples/peer-connection against it.
MODULES := netaddr logging transport internal/codec internal/aes internal/randutil \
           stun stunclient turn mdns sdp rtp rtcp srtp ice dtls sctp datachannel
# The modules that decode input from the network, and so get the extra passes.
CODECS  := internal/codec internal/aes netaddr stun sdp rtp rtcp srtp sctp turn mdns
EXAMPLES := $(notdir $(patsubst %/,%,$(wildcard examples/*/)))
# The root module's own files, and every path the whole-project commands act on.
#
# These are listed rather than using ".", because "." is whatever happens to be
# in the working directory - and on CI that includes the V compiler itself,
# which setup-v clones into the workspace. Walking into it makes `v fmt` check
# V's source tree and `v test` run V's own test suite.
ROOT_V  := $(wildcard *.v)
VPATHS  := $(MODULES) $(ROOT_V) examples

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
	$(V) test $(MODULES) $(ROOT_V)

.PHONY: fmt
fmt:
	$(V) fmt -w $(VPATHS)

.PHONY: fmt-check
fmt-check:
	$(V) fmt -verify $(VPATHS)

.PHONY: vet
vet:
	$(V) vet $(MODULES) $(ROOT_V)

.PHONY: build
build:
	@set -e; for module in $(MODULES); do \
		echo "  check $$module"; \
		$(V) -shared -check "$$module"; \
	done

.PHONY: build-prod
build-prod:
	@set -e; for module in $(MODULES); do \
		echo "  check $$module (prod)"; \
		$(V) -prod -shared -check "$$module"; \
	done

.PHONY: examples
examples:
	@set -e; for example in $(EXAMPLES); do \
		echo "  build $$example"; \
		$(V) -o "/tmp/webrtc-v-$$example" "examples/$$example"; \
	done

.PHONY: bench
bench:
	@# -prod matters here: the stack is CPU-bound on AES, and an unoptimised
	@# build measures the C compiler rather than this code.
	$(V) -prod run examples/throughput
