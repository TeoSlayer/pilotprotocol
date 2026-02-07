.PHONY: all build test clean vet ci release

BINDIR := bin
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

# Core binaries that agents need
CORE_BINS := daemon pilotctl gateway

all: build

build:
	@mkdir -p $(BINDIR)
	go build -o $(BINDIR)/registry ./cmd/registry
	go build -o $(BINDIR)/beacon ./cmd/beacon
	go build -o $(BINDIR)/daemon ./cmd/daemon
	go build -o $(BINDIR)/rendezvous ./cmd/rendezvous
	go build -o $(BINDIR)/pilotctl ./cmd/pilotctl
	go build -o $(BINDIR)/nameserver ./cmd/nameserver
	go build -o $(BINDIR)/gateway ./cmd/gateway
	go build -o $(BINDIR)/webserver ./examples/webserver
	go build -o $(BINDIR)/client ./examples/client
	go build -o $(BINDIR)/echo ./examples/echo
	go build -o $(BINDIR)/dataexchange ./examples/dataexchange
	go build -o $(BINDIR)/eventstream ./examples/eventstream
	go build -o $(BINDIR)/secure ./examples/secure

test:
	go test -parallel 4 -count=1 ./tests/...

clean:
	rm -rf $(BINDIR)

# Build for Linux (GCP deployment)
build-linux:
	@mkdir -p $(BINDIR)
	GOOS=linux GOARCH=amd64 go build -o $(BINDIR)/rendezvous-linux ./cmd/rendezvous
	GOOS=linux GOARCH=amd64 go build -o $(BINDIR)/daemon-linux ./cmd/daemon
	GOOS=linux GOARCH=amd64 go build -o $(BINDIR)/pilotctl-linux ./cmd/pilotctl
	GOOS=linux GOARCH=amd64 go build -o $(BINDIR)/nameserver-linux ./cmd/nameserver
	GOOS=linux GOARCH=amd64 go build -o $(BINDIR)/gateway-linux ./cmd/gateway
	GOOS=linux GOARCH=amd64 go build -o $(BINDIR)/echo-linux ./examples/echo
	GOOS=linux GOARCH=amd64 go build -o $(BINDIR)/client-linux ./examples/client
	GOOS=linux GOARCH=amd64 go build -o $(BINDIR)/webserver-linux ./examples/webserver
	GOOS=linux GOARCH=amd64 go build -o $(BINDIR)/dataexchange-linux ./examples/dataexchange
	GOOS=linux GOARCH=amd64 go build -o $(BINDIR)/eventstream-linux ./examples/eventstream
	GOOS=linux GOARCH=amd64 go build -o $(BINDIR)/secure-linux ./examples/secure

vet:
	go vet ./...

ci: vet test build build-linux
	@echo "CI: all checks passed"

# Cross-platform release builds
release:
	@mkdir -p $(BINDIR)/release
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d/ -f1); \
		arch=$$(echo $$platform | cut -d/ -f2); \
		echo "Building $$os/$$arch..."; \
		for bin in $(CORE_BINS); do \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" \
				-o $(BINDIR)/release/pilot-$$bin-$$os-$$arch ./cmd/$$bin; \
		done; \
		tar -czf $(BINDIR)/release/pilot-$$os-$$arch.tar.gz \
			-C $(BINDIR)/release pilot-daemon-$$os-$$arch pilot-pilotctl-$$os-$$arch pilot-gateway-$$os-$$arch; \
		rm $(BINDIR)/release/pilot-daemon-$$os-$$arch $(BINDIR)/release/pilot-pilotctl-$$os-$$arch $(BINDIR)/release/pilot-gateway-$$os-$$arch; \
	done
	@echo "Release archives in $(BINDIR)/release/"

# Docker
docker:
	docker build -t pilot-rendezvous .
