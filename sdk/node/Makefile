.PHONY: help install build test clean binaries dist

help:
	@echo "Pilot Protocol Node.js SDK - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make install   - Install dependencies"
	@echo "  make build     - Compile TypeScript to dist/"
	@echo "  make binaries  - Build Go binaries (daemon, pilotctl, gateway, libpilot)"
	@echo "  make test      - Run tests"
	@echo "  make dist      - Full build: binaries + TypeScript + pack"
	@echo "  make clean     - Remove build artifacts and node_modules"
	@echo ""

install:
	npm install

build:
	npm run build

binaries:
	./scripts/build-binaries.sh

test:
	npm test

dist: binaries build
	npm pack

clean:
	rm -rf dist/ node_modules/ bin/ *.tgz
