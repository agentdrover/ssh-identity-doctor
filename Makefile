.PHONY: check lint format-check typecheck test

check: lint format-check typecheck test

lint:
	uv run --locked ruff check src tests

format-check:
	uv run --locked ruff format --check src tests

typecheck:
	uv run --locked mypy --strict src

test:
	uv run --locked pytest -q
