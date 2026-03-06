# Makefile for integration tests

.PHONY: help test test-cli test-sdk build clean results

help:
	@echo "Pilot Protocol Integration Tests"
	@echo ""
	@echo "Usage:"
	@echo "  make test        - Run all integration tests"
	@echo "  make test-cli    - Run CLI tests only"
	@echo "  make test-sdk    - Run Python SDK tests only"
	@echo "  make build       - Build Docker image"
	@echo "  make clean       - Clean up containers and results"
	@echo "  make results     - Show test results"

test:
	@echo "[`date '+%Y-%m-%d %H:%M:%S'`] Running all integration tests..."
	@mkdir -p results
	@echo "[`date '+%Y-%m-%d %H:%M:%S'`] Building Docker image..."
	@set -o pipefail; \
		DOCKER_BUILDKIT=1 timeout 300 docker-compose up --build --abort-on-container-exit 2>&1 | \
		tee /tmp/docker-output.log; \
		EXIT_CODE=$$?; \
		docker-compose down -v 2>/dev/null; \
		if [ "$$EXIT_CODE" = "124" ]; then \
			echo "[`date '+%Y-%m-%d %H:%M:%S'`] Tests timed out after 5 minutes"; \
			exit 1; \
		elif [ "$$EXIT_CODE" != "0" ]; then \
			echo "[`date '+%Y-%m-%d %H:%M:%S'`] Docker exited with code $$EXIT_CODE"; \
		fi
	@echo ""
	@echo "========================================="
	@echo "[`date '+%Y-%m-%d %H:%M:%S'`] Test Results"
	@echo "========================================="
	@if [ -f results/cli_results.txt ]; then \
		echo ""; \
		echo "[`date '+%Y-%m-%d %H:%M:%S'`] --- CLI Tests ---"; \
		sed 's/\x1b\[[0-9;]*m//g' results/cli_results.txt | while IFS= read -r line; do \
			if echo "$$line" | grep -qE '^\['; then \
				echo "$$line"; \
			elif [ -n "$$line" ]; then \
				echo "[`date '+%Y-%m-%d %H:%M:%S'`] $$line"; \
			fi; \
		done; \
	else \
		echo "[`date '+%Y-%m-%d %H:%M:%S'`] WARNING: results/cli_results.txt not found"; \
	fi
	@if [ -f results/sdk_results.txt ]; then \
		echo ""; \
		echo "[`date '+%Y-%m-%d %H:%M:%S'`] --- SDK Tests ---"; \
		sed 's/\x1b\[[0-9;]*m//g' results/sdk_results.txt | while IFS= read -r line; do \
			if echo "$$line" | grep -qE '^\['; then \
				echo "$$line"; \
			elif [ -n "$$line" ]; then \
				echo "[`date '+%Y-%m-%d %H:%M:%S'`] $$line"; \
			fi; \
		done; \
	else \
		echo "[`date '+%Y-%m-%d %H:%M:%S'`] WARNING: results/sdk_results.txt not found"; \
	fi
	@echo ""
	@echo "========================================="
	@echo "[`date '+%Y-%m-%d %H:%M:%S'`] Full results saved to results/"
	@echo "========================================="

test-cli:
	@echo "Running CLI integration tests..."
	@mkdir -p results
	docker build -f Dockerfile -t pilot-integration-test ../..
	docker run --rm pilot-integration-test /bin/bash /tests/test_cli.sh | tee results/cli_results.txt

test-sdk:
	@echo "Running SDK integration tests..."
	@mkdir -p results
	docker build -f Dockerfile -t pilot-integration-test ../..
	docker run --rm pilot-integration-test python /tests/test_sdk.py | tee results/sdk_results.txt

build:
	@echo "Building integration test image..."
	docker build -f Dockerfile -t pilot-integration-test ../..

clean:
	@echo "Cleaning up..."
	docker-compose down -v 2>/dev/null || true
	docker rmi pilot-integration-test 2>/dev/null || true
	rm -rf results/

results:
	@if [ -f results/cli_results.txt ]; then \
		echo "[`date '+%Y-%m-%d %H:%M:%S'`] === CLI Test Results ==="; \
		sed 's/\x1b\[[0-9;]*m//g' results/cli_results.txt; \
		echo ""; \
	else \
		echo "[`date '+%Y-%m-%d %H:%M:%S'`] No CLI results found"; \
	fi
	@if [ -f results/sdk_results.txt ]; then \
		echo "[`date '+%Y-%m-%d %H:%M:%S'`] === SDK Test Results ==="; \
		sed 's/\x1b\[[0-9;]*m//g' results/sdk_results.txt; \
	else \
		echo "[`date '+%Y-%m-%d %H:%M:%S'`] No SDK results found"; \
	fi
