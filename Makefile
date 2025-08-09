# OpenShift AI Security Dashboard Makefile
.PHONY: help install dev test lint format clean db-init db-migrate db-seed build docker-build docker-run

# Default target
help:
	@echo "OpenShift AI Security Dashboard - Development Commands"
	@echo ""
	@echo "Setup Commands:"
	@echo "  install        Install dependencies using uv"
	@echo "  install-dev    Install development dependencies"
	@echo ""
	@echo "Development Commands:"
	@echo "  dev            Run development server"
	@echo "  test           Run pytest suite"
	@echo "  test-cov       Run tests with coverage report"
	@echo "  lint           Run flake8 linter"
	@echo "  format         Format code with black"
	@echo "  type-check     Run mypy type checking"
	@echo "  clean          Clean cache and temp files"
	@echo ""
	@echo "Database Commands:"
	@echo "  db-init        Initialize database schema"
	@echo "  db-migrate     Run database migrations"
	@echo "  db-seed        Seed with test data"
	@echo "  db-reset       Reset database (clean + init)"
	@echo ""
	@echo "Build Commands:"
	@echo "  build          Build application"
	@echo "  docker-build   Build Docker image"
	@echo "  docker-run     Run in Docker container"

# Installation commands
install:
	@echo "Installing dependencies with uv..."
	uv sync

install-dev:
	@echo "Installing development dependencies..."
	uv sync --extra dev

# Development commands
dev:
	@echo "Starting Streamlit development server..."
	uv run streamlit run src/app.py --server.port 8501 --server.address 0.0.0.0

test:
	@echo "Running pytest suite..."
	uv run pytest

test-cov:
	@echo "Running tests with coverage..."
	uv run pytest --cov=src --cov-report=html --cov-report=term-missing

lint:
	@echo "Running flake8 linter..."
	uv run flake8 src tests

format:
	@echo "Formatting code with black..."
	uv run black src tests
	@echo "Code formatting complete."

format-check:
	@echo "Checking code formatting..."
	uv run black --check src tests

type-check:
	@echo "Running mypy type checking..."
	uv run mypy src

clean:
	@echo "Cleaning cache and temporary files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -rf htmlcov
	rm -rf dist
	rm -rf build
	rm -f .coverage
	rm -f *.db
	@echo "Cleanup complete."

# Database commands
db-init:
	@echo "Initializing database schema..."
	uv run python -m src.database.connection init

db-migrate:
	@echo "Running database migrations..."
	uv run alembic upgrade head

db-seed:
	@echo "Seeding database with test data..."
	uv run python -m src.database.connection seed

db-reset: clean db-init
	@echo "Database reset complete."

# Quality checks (run all)
check: format-check lint type-check test
	@echo "All quality checks passed!"

# Build commands
build:
	@echo "Building application..."
	uv run python -m build

docker-build:
	@echo "Building Docker image..."
	docker build -t openshift-ai-security-dashboard .

docker-run:
	@echo "Running Docker container..."
	docker run -p 8501:8501 openshift-ai-security-dashboard

# CI/CD helpers
ci-install:
	@echo "Installing for CI environment..."
	pip install -e ".[dev]"

ci-test: format-check lint type-check test-cov
	@echo "CI pipeline tests complete."

# Development workflow
setup: install db-init
	@echo "Development environment setup complete!"
	@echo "Run 'make dev' to start the development server."

# Pre-commit setup
pre-commit-install:
	@echo "Installing pre-commit hooks..."
	uv run pre-commit install
	@echo "Pre-commit hooks installed."

pre-commit-run:
	@echo "Running pre-commit hooks..."
	uv run pre-commit run --all-files