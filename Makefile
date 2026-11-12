MODULES := . api sdk
export GOTOOLCHAIN := auto

.PHONY: test race vet lint e2e workspace

test:                       ## unit tests, every module
	@for m in $(MODULES); do (cd $$m && go test ./...) || exit 1; done

race:                       ## unit tests with the race detector (what CI runs)
	@for m in $(MODULES); do (cd $$m && go test -race ./...) || exit 1; done

vet:
	@for m in $(MODULES); do (cd $$m && go vet ./... && GOOS=linux go vet ./...) || exit 1; done

GOLANGCI := $(CURDIR)/bin/golangci-lint

$(GOLANGCI):                 ## pinned linter, built into ./bin (gitignored)
	GOBIN=$(CURDIR)/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0

lint: $(GOLANGCI)           ## every module, for this OS and for Linux
	@for m in $(MODULES); do (cd $$m && $(GOLANGCI) run ./... && GOOS=linux $(GOLANGCI) run ./...) || exit 1; done

e2e:                        ## the test loop on real machines (Lima on macOS, this machine on Linux)
	go test -tags e2e -count=1 -v -timeout 30m ./test/e2e/...

workspace:                  ## write ../go.work for core and any sibling provider repos
	hack/workspace.sh
