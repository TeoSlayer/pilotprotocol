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
	# Per-platform sub-package bin/ trees (populated by build-binaries.sh
	# for local dev, by the publish workflow in CI). Wipe the contents but
	# keep the per-platform package.json files in place.
	find packages -mindepth 2 -maxdepth 3 -type f \
	    \( -name 'pilot-*' -o -name 'pilotctl' -o -name 'libpilot.*' \) \
	    -delete 2>/dev/null || true
	find packages -mindepth 2 -maxdepth 3 -type d -name bin -empty -delete 2>/dev/null || true
