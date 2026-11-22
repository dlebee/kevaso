MODULES := . api sdk
export GOTOOLCHAIN := auto

.PHONY: test test-short race vet vet-tags lint e2e e2e-ci where fuzz stress contention mutate workspace proto plugins lab-up lab-down lab-list release-dry

# A worktree lab on the EPYC. LAB is the name. PAIR=1 is two machine VMs for the
# two-machine metal tests (Kevaso is not installed; the tests install it).
# VCPU=n is each pair-lab machine's vCPUs (default 8; see testbed/lab).
# LAB_HOST, LAB_SSH_KEY and LAB_HOSTKEY override the host (see testbed/lab/README.md).
lab-up: ## fresh lab (LAB=name, PAIR=1 for two machines, VCPU=n, RECREATE=1 to replace one)
	@test -n "$(LAB)" || { echo "usage: make lab-up LAB=name [PAIR=1] [VCPU=n] [RECREATE=1]" >&2; exit 2; }
	GOPROXY=off go run ./testbed/lab/cmd/kvlab up --name "$(LAB)" $(if $(filter 1,$(PAIR)),--pair,) $(if $(VCPU),--vcpu $(VCPU),) $(if $(RECREATE),--recreate,)

lab-down: ## remove lab LAB and nothing else
	@test -n "$(LAB)" || { echo "usage: make lab-down LAB=name" >&2; exit 2; }
	GOPROXY=off go run ./testbed/lab/cmd/kvlab down --name "$(LAB)"

lab-list: ## labs on the host
	GOPROXY=off go run ./testbed/lab/cmd/kvlab list

test:                       ## unit tests, every module
	@for m in $(MODULES); do (cd $$m && go test ./...) || exit 1; done

race:                       ## unit tests with the race detector (what CI runs)
	@for m in $(MODULES); do (cd $$m && go test -race ./...) || exit 1; done

vet:
	@for m in $(MODULES); do (cd $$m && go vet ./... && GOOS=linux go vet ./...) || exit 1; done
	GOOS=windows go vet $(WINDOWS_PKGS)

WINDOWS_PKGS := ./cmd/kvo/... ./internal/cli/kvo/... ./internal/kvoplugin/... ./examples/kvo-plugin/...

GOLANGCI := $(CURDIR)/bin/golangci-lint

$(GOLANGCI):                 ## pinned linter, built into ./bin (gitignored)
	GOBIN=$(CURDIR)/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0

lint: $(GOLANGCI)           ## every module, for this OS and for Linux
	@for m in $(MODULES); do (cd $$m && $(GOLANGCI) run ./... && GOOS=linux $(GOLANGCI) run ./...) || exit 1; done
	GOOS=windows $(GOLANGCI) run $(WINDOWS_PKGS)

e2e:                        ## the test loop on real machines (Lima on macOS, this machine on Linux)
	go test -tags e2e -count=1 -v -timeout 30m ./test/e2e/...

e2e-ci:                     ## what CI's e2e job runs: e2e, and a failure when a test in test/e2e/ci-expected.txt skips
	bash -o pipefail -c 'go test -tags e2e -count=1 -json -timeout 30m ./test/e2e/... | go run ./hack/skipbudget test/e2e/ci-expected.txt'

test-short:                 ## the quick local loop: -short shrinks the property and soak tests
	@for m in $(MODULES); do (cd $$m && go test -short ./...) || exit 1; done

vet-tags:                   ## compile every build tag (e2e, metal) for linux and darwin, so tagged test code cannot rot
	@for os in linux darwin; do for t in e2e metal; do echo "go vet -tags $$t (GOOS=$$os)"; GOOS=$$os go vet -tags $$t ./... || exit 1; done; done

where:                      ## regenerate test/WHERE.md (which tests exist under each build tag, and where they run)
	go run ./hack/where > test/WHERE.md

fuzz:                       ## fuzz every fuzzer for FUZZTIME (default 60s) each; the seed corpus already runs in every `make test`
	hack/fuzz.sh $(FUZZTIME)

stress:                     ## the property, stress, race and election tests, three times each, under the race detector (nightly)
	go test -race -count=3 -timeout 40m -run 'Property|Stress|Race|Simulated|Survive|Join|Light|Lease' ./internal/store ./internal/controlplane ./internal/leader ./internal/rbac ./internal/moves ./internal/scheduler ./internal/names ./internal/apiserver ./builtin/kni

contention:                 ## the suite under load: four copies of the integration and controller tests at once, GOMAXPROCS=2, -race (nightly)
	hack/contention.sh

mutate:                     ## prove the safety guards cannot be removed without a test failing (slow: about an hour; nightly). See hack/mutate/README.md
	go run ./hack/mutate -j 3

workspace:                  ## write ../go.work for core and any sibling provider repos
	hack/workspace.sh

proto:                      ## regenerate sdk/kplugin/kpluginpb from its .proto (protoc + the pinned generators in ./bin)
	GOBIN=$(CURDIR)/bin go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.10
	GOBIN=$(CURDIR)/bin go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
	cd sdk/kplugin/kpluginpb && PATH=$(CURDIR)/bin:$$PATH protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative kplugin.proto

plugins:                    ## a local, signed kvo plugin index in ./bin/plugins (whoami for every platform; panes on macOS)
	hack/plugins.sh

RELEASE_VERSION ?= v0.0.0-dry

release-dry:                ## what a tag release builds, unsigned, into dist/release-dry (RELEASE_VERSION=vX.Y.Z)
	rm -rf dist/release-dry
	@for t in darwin/arm64 darwin/amd64 windows/amd64 linux/amd64 linux/arm64; do \
		hack/release/build.sh $(RELEASE_VERSION) $${t%/*} $${t#*/} dist/release-dry/build/$${t%/*}-$${t#*/} || exit 1; \
	done
	hack/release/package.sh $(RELEASE_VERSION) dist/release-dry/build dist/release-dry/out
	cd dist/release-dry/out && shasum -a 256 * > SHA256SUMS && cat SHA256SUMS
