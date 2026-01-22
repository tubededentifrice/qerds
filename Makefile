# QERDS Development Makefile
# All commands should be run via Docker for reproducibility

.PHONY: help install lint format typecheck test test-cov clean

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
	@echo "Quality gates (run all checks):"
	@echo "  make check       Run all local checks"
	@echo "  make docker-check Run all checks in Docker"

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
