# QERDS Development Makefile
# All commands should be run via Docker for reproducibility

.PHONY: help install lint format typecheck test test-cov clean check-traceability \
       test-env-up test-env-down test-env-status test-docker test-docker-cov \
       check-network check-network-prod

# Default target
help:
	@echo "QERDS Development Commands"
	@echo ""
	@echo "Local development (requires venv):"
	@echo "  make install     Install package in editable mode with dev deps"
	@echo "  make lint        Run ruff linter"
	@echo "  make format      Run ruff formatter"
	@echo "  make typecheck   Run mypy type checker"
	@echo "  make test        Run pytest"
	@echo "  make test-cov    Run pytest with coverage"
	@echo "  make clean       Remove build artifacts"
	@echo ""
	@echo "Docker commands (recommended):"
	@echo "  make docker-lint      Run linter in Docker"
	@echo "  make docker-format    Run formatter in Docker"
	@echo "  make docker-test      Run tests in Docker"
	@echo "  make docker-typecheck Run type checker in Docker"
	@echo ""
	@echo "Test environment:"
	@echo "  make test-env-up      Start test containers (postgres, minio, mailpit)"
	@echo "  make test-env-down    Stop test containers and remove volumes"
	@echo "  make test-env-status  Show test container status"
	@echo "  make test-docker      Run tests against test containers"
	@echo "  make test-docker-cov  Run tests with coverage against test containers"
	@echo ""
	@echo "Quality gates (run all checks):"
	@echo "  make check       Run all local checks"
	@echo "  make docker-check Run all checks in Docker"
	@echo ""
	@echo "Compliance:"
	@echo "  make check-traceability  Validate requirements traceability coverage"
	@echo "  make check-network       Validate network security posture (REQ-D07)"
	@echo "  make check-network-prod  Validate network security (production mode)"

# Local development targets
install:
	pip install -e ".[dev]"

lint:
	ruff check src tests

format:
	ruff format src tests

format-check:
	ruff format --check src tests

typecheck:
	mypy src

test:
	pytest

test-cov:
	pytest --cov --cov-report=term-missing --cov-report=html

# Combined quality gate
check: lint format-check typecheck test

# Docker targets (for CI/CD and reproducible builds)
docker-lint:
	docker compose exec qerds-api ruff check src tests

docker-format:
	docker compose exec qerds-api ruff format src tests

docker-format-check:
	docker compose exec qerds-api ruff format --check src tests

docker-typecheck:
	docker compose exec qerds-api mypy src

docker-test:
	docker compose exec qerds-api pytest

docker-test-cov:
	docker compose exec qerds-api pytest --cov --cov-report=term-missing

docker-check: docker-lint docker-format-check docker-typecheck docker-test

# ---------------------------------------------------------------------------
# Test Environment (isolated test containers)
# ---------------------------------------------------------------------------

# Start test containers (separate from dev containers)
test-env-up:
	docker compose -f docker/docker-compose.test.yml up -d
	@echo "Waiting for services to be healthy..."
	@docker compose -f docker/docker-compose.test.yml ps
	@sleep 5
	@echo "Test environment ready."
	@echo "  Postgres: localhost:5433"
	@echo "  MinIO:    localhost:9002 (console: localhost:9003)"
	@echo "  Mailpit:  localhost:8026 (SMTP: localhost:1026)"

# Stop test containers and clean up
test-env-down:
	docker compose -f docker/docker-compose.test.yml down -v

# Show test container status
test-env-status:
	docker compose -f docker/docker-compose.test.yml ps

# Run tests against the test environment (requires test-env-up first)
test-docker: test-env-up
	TEST_DATABASE_URL=postgresql+psycopg://qerds:qerds_dev_password@localhost:5433/qerds_test \
	TEST_S3_ENDPOINT=http://localhost:9002 \
	TEST_S3_ACCESS_KEY=qerds_minio \
	TEST_S3_SECRET_KEY=qerds_minio_secret \
	pytest tests/

# Run tests with coverage against the test environment
test-docker-cov: test-env-up
	TEST_DATABASE_URL=postgresql+psycopg://qerds:qerds_dev_password@localhost:5433/qerds_test \
	TEST_S3_ENDPOINT=http://localhost:9002 \
	TEST_S3_ACCESS_KEY=qerds_minio \
	TEST_S3_SECRET_KEY=qerds_minio_secret \
	pytest tests/ --cov=src/qerds --cov-report=term-missing --cov-report=html

# Compliance targets (REQ-A04)
check-traceability:
	@python3 scripts/check-traceability.py

# Network security validation (REQ-D07)
check-network:
	@python3 scripts/check-network-security.py

check-network-prod:
	@python3 scripts/check-network-security.py --production

# Cleanup
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf src/*.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
