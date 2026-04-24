# Makefile for integration tests

# Use bash instead of sh for pipefail support
SHELL := /bin/bash

# Docker Compose v2 (`docker compose`); override with DOCKER_COMPOSE=docker-compose for v1
DOCKER_COMPOSE ?= docker compose
# Overall timeout for `make test`; 0 disables
TEST_TIMEOUT   ?= 1800

.PHONY: help test test-cli test-sdk test-nat test-nat-parallel test-chaos build clean results

help:
	@echo "Pilot Protocol Integration Tests"
	@echo ""
	@echo "Usage:"
	@echo "  make test               - Run compose-based CLI+SDK integration suite"
	@echo "  make test-cli           - Run CLI tests only"
	@echo "  make test-sdk           - Run Python SDK tests only"
	@echo "  make test-nat           - Run full NAT suite (run_all_nat.sh)"
	@echo "  make test-nat-parallel  - Run NAT suite in parallel (run_nat_suite_parallel.sh)"
	@echo "  make test-chaos         - Run chaos tests (test_chaos_*.sh)"
	@echo "  make build              - Build Docker image"
	@echo "  make clean              - Clean up containers and results"
	@echo "  make results            - Show test results"
	@echo ""
	@echo "Env: DOCKER_COMPOSE=$(DOCKER_COMPOSE)  TEST_TIMEOUT=$(TEST_TIMEOUT)"

test:
	@echo "[`date '+%Y-%m-%d %H:%M:%S'`] Running all integration tests..."
	@mkdir -p results
	@echo "[`date '+%Y-%m-%d %H:%M:%S'`] Building Docker image..."
	@set -o pipefail; \
		if [ "$(TEST_TIMEOUT)" != "0" ]; then TO="timeout $(TEST_TIMEOUT)"; else TO=""; fi; \
		DOCKER_BUILDKIT=1 $$TO $(DOCKER_COMPOSE) up --build --abort-on-container-exit 2>&1 | \
		tee /tmp/docker-output.log; \
		EXIT_CODE=$$?; \
		$(DOCKER_COMPOSE) down -v 2>/dev/null; \
		if [ "$$EXIT_CODE" = "124" ]; then \
			echo "[`date '+%Y-%m-%d %H:%M:%S'`] Tests timed out after $(TEST_TIMEOUT)s"; \
			exit 1; \
		elif [ "$$EXIT_CODE" != "0" ]; then \
			echo "[`date '+%Y-%m-%d %H:%M:%S'`] Docker exited with code $$EXIT_CODE"; \
			exit $$EXIT_CODE; \
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
	docker build -f Dockerfile -t pilot-integration-test ../../..
	docker run --rm pilot-integration-test /bin/bash /tests/test_cli.sh | tee results/cli_results.txt

test-sdk:
	@echo "Running SDK integration tests..."
	@mkdir -p results
	docker build -f Dockerfile -t pilot-integration-test ../../..
	docker run --rm pilot-integration-test python /tests/test_sdk.py | tee results/sdk_results.txt

build:
	@echo "Building integration test image..."
	docker build -f Dockerfile -t pilot-integration-test ../../..

test-nat:
	@echo "[`date '+%Y-%m-%d %H:%M:%S'`] Running full NAT suite..."
	./run_all_nat.sh

test-nat-parallel:
	@echo "[`date '+%Y-%m-%d %H:%M:%S'`] Running NAT suite in parallel..."
	./run_nat_suite_parallel.sh

test-chaos:
	@echo "[`date '+%Y-%m-%d %H:%M:%S'`] Running chaos tests..."
	@for t in test_chaos_*.sh; do \
		echo "[`date '+%Y-%m-%d %H:%M:%S'`] --- $$t ---"; \
		./$$t || exit $$?; \
	done

clean:
	@echo "Cleaning up..."
	$(DOCKER_COMPOSE) down -v 2>/dev/null || true
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
