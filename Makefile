.PHONY: install dev db db-stop up down migrate seed test test-sdk test-cloud lint format serve clean

# Install all workspace dependencies
install:
	uv sync --all-packages --all-extras

# Start local dev environment (Postgres only)
db:
	docker compose up -d postgres
	@echo "Waiting for Postgres..."
	@until docker compose exec postgres pg_isready -U aktov > /dev/null 2>&1; do sleep 1; done
	@echo "Postgres ready at localhost:5432"

db-stop:
	docker compose down

# Start full stack (Postgres + Cloud)
up:
	docker compose up -d
	@echo "Aktov running at http://localhost:8000"

down:
	docker compose down

# Run Alembic migrations (requires Postgres running)
migrate:
	cd cloud && uv run alembic upgrade head

# Seed dev data (org, API key, 12 system rules)
seed:
	uv run python cloud/src/aktov_cloud/scripts/seed_dev.py

# Run all tests
test:
	uv run pytest -v

# Run SDK tests only
test-sdk:
	uv run pytest sdk/tests -v

# Run Cloud tests only
test-cloud:
	uv run pytest cloud/tests -v

# Lint
lint:
	uv run ruff check .

# Format
format:
	uv run ruff format .
	uv run ruff check --fix .

# Run the cloud service locally (without Docker)
serve:
	uv run uvicorn aktov_cloud.main:app --reload --host 0.0.0.0 --port 8000

# Clean build artifacts
clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf dist/ build/
