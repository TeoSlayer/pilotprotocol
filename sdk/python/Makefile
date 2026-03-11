.PHONY: help test test-coverage build publish publish-test clean install install-dev coverage-badge

help:
	@echo "Pilot Protocol Python SDK - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make install          - Install package in development mode"
	@echo "  make install-dev      - Install with development dependencies"
	@echo "  make test             - Run tests"
	@echo "  make test-coverage    - Run tests with coverage reports"
	@echo "  make coverage-badge   - Generate coverage badge SVG"
	@echo "  make build            - Build wheel and sdist for PyPI"
	@echo "  make publish-test     - Publish to TestPyPI"
	@echo "  make publish          - Publish to PyPI (production)"
	@echo "  make clean            - Remove build artifacts and cache"
	@echo ""

install:
	pip install -e .

install-dev:
	pip install -e .[dev]

test:
	pytest tests/ -v

test-coverage:
	./scripts/test-coverage.sh

coverage-badge:
	./scripts/generate-coverage-badge.sh

build:
	./scripts/build.sh

publish-test:
	./scripts/publish.sh testpypi

publish:
	@echo "⚠️  WARNING: This will publish to PyPI (production)!"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		./scripts/publish.sh pypi; \
	else \
		echo "Aborted."; \
	fi

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache htmlcov coverage.json .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
