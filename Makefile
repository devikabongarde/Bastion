.PHONY: install lint typecheck test test-unit test-integration db-upgrade api web-install web-check web-build

install:
	uv sync --all-packages --group dev
	corepack pnpm install --frozen-lockfile

lint:
	uv run ruff check apps packages tests migrations

typecheck:
	uv run pyright
	corepack pnpm --filter @baselineguard/web typecheck

test:
	uv run pytest
	corepack pnpm --filter @baselineguard/web test

test-unit:
	uv run pytest -m 'not integration and not live'

test-integration:
	uv run pytest -m integration

db-upgrade:
	uv run alembic upgrade head

api:
	uv run uvicorn baselineguard_api.main:app --reload --host 127.0.0.1 --port 8000

web-install:
	corepack pnpm install --frozen-lockfile

web-check:
	corepack pnpm --filter @baselineguard/web typecheck

web-build:
	corepack pnpm --filter @baselineguard/web build

