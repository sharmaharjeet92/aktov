FROM python:3.12-slim

WORKDIR /app

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy workspace root files needed for dependency resolution
COPY pyproject.toml uv.lock ./
COPY sdk/ sdk/
COPY cloud/ cloud/
COPY rules/ rules/

# Install all workspace packages
RUN uv sync --all-packages --all-extras --frozen

# Run migrations then start the server
CMD ["sh", "-c", "uv run alembic -c cloud/alembic.ini upgrade head && uv run uvicorn aktov_cloud.main:app --host 0.0.0.0 --port 8000"]

EXPOSE 8000
