.PHONY: all help build build-linux test vet fmt lint coverage coverage-html clean \
        release integration ci ci-fast \
        test-integration-quick test-integration-full

BINDIR    := bin
COVERDIR  := coverage
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS   := -s -w -X main.version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

# Binaries built from ./cmd
CMD_BINS     := daemon pilotctl

# Binaries included in release archives
RELEASE_BINS := daemon pilotctl

all: vet test build

help:
	@echo "Pilot Protocol — Makefile targets"
	@echo ""
	@echo "  build           Build daemon + pilotctl into $(BINDIR)/"
	@echo "  build-linux     Cross-compile for linux/amd64"
	@echo "  release         Build cross-platform release archives"
	@echo "  test            Run unit + in-repo tests"
	@echo "  vet             go vet ./..."
	@echo "  fmt             gofmt -s -w ."
	@echo "  lint            golangci-lint run (if installed)"
	@echo "  coverage        Run tests with coverage profile"
	@echo "  coverage-html   Open coverage report in HTML"
	@echo "  integration     Run local Docker-based integration suite"
	@echo "  clean           Remove $(BINDIR)/ and $(COVERDIR)/"

# --- Build -------------------------------------------------------------------

define build_bin
	go build $(if $(1),-ldflags "$(LDFLAGS)") -o $(BINDIR)/$(2)$(3) $(4)

endef

build:
	@mkdir -p $(BINDIR)
	$(foreach b,$(CMD_BINS),$(call build_bin,,$(b),,./cmd/$(b)))

build-linux:
	@mkdir -p $(BINDIR)
	$(foreach b,$(CMD_BINS),GOOS=linux GOARCH=amd64 $(call build_bin,,$(b),-linux,./cmd/$(b)))

# --- Tests / quality ---------------------------------------------------------

test:
	go test -parallel 4 -count=1 ./pkg/... ./tests/

vet:
	go vet ./...

fmt:
	gofmt -s -w .

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not installed; see https://golangci-lint.run"; exit 1; }
	golangci-lint run

coverage:
	@mkdir -p $(COVERDIR)
	@cd tests && go test -parallel 4 -count=1 \
		-coverprofile=../$(COVERDIR)/coverage.out -covermode=atomic -timeout 5m
	@go tool cover -func=$(COVERDIR)/coverage.out | tail -1 | awk '{print "Total coverage: " $$3}'
	@go tool cover -func=$(COVERDIR)/coverage.out -o=$(COVERDIR)/coverage.txt

coverage-html: coverage
	@go tool cover -html=$(COVERDIR)/coverage.out -o=$(COVERDIR)/coverage.html
	@echo "Coverage report generated: $(COVERDIR)/coverage.html"

integration:
	$(MAKE) -C tests/integration/local test

# --- Tiered test suites ------------------------------------------------------
# Tier 1 — CI fast (<2min). Pure Go unit + package tests. Runs on every push.
ci-fast: vet
	go test ./pkg/... ./cmd/... ./internal/... -short -timeout 120s -parallel 4

# Tier 2 — integration quick (<10min). Docker-based tests that need a live
# cross-process environment AND finish fast. Skips long-running durability,
# resilience, and chaos tests. Runs pre-merge.
test-integration-quick:
	cd tests/integration/local && \
	  if [ -f QUICK.txt ]; then \
	    bash ./run-all.sh -j 10 $$(grep -v '^#' QUICK.txt | tr '\n' ' '); \
	  else \
	    echo "QUICK.txt missing — run make test-integration-full"; exit 1; \
	  fi

# Tier 3 — integration full (~30min @ -j 10). Everything including 10min+
# durability, resilience, chaos. Nightly or on-demand.
test-integration-full:
	cd tests/integration/local && bash ./run-all.sh -j 10

# --- Release -----------------------------------------------------------------

release:
	@mkdir -p $(BINDIR)/release
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d/ -f1); \
		arch=$$(echo $$platform | cut -d/ -f2); \
		echo "Building $$os/$$arch..."; \
		mkdir -p $(BINDIR)/release/$$os-$$arch; \
		for bin in $(RELEASE_BINS); do \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" \
				-o $(BINDIR)/release/$$os-$$arch/$$bin ./cmd/$$bin; \
		done; \
		tar -czf $(BINDIR)/release/pilot-$$os-$$arch.tar.gz \
			-C $(BINDIR)/release/$$os-$$arch .; \
		rm -rf $(BINDIR)/release/$$os-$$arch; \
	done
	@cd $(BINDIR)/release && shasum -a 256 *.tar.gz > checksums.txt
	@echo "Release archives in $(BINDIR)/release/"

# --- Utility -----------------------------------------------------------------

ci: vet test build build-linux
	@echo "CI: all checks passed"

clean:
	rm -rf $(BINDIR) $(COVERDIR)
