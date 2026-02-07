.PHONY: all build test clean vet ci

BINDIR := bin

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
	go test ./tests/...

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

# Docker
docker:
	docker build -t pilot-rendezvous .
