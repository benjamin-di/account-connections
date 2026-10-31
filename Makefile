.PHONY: check
check:
	uv run --locked ruff check .
	uv run --locked ruff format --check .
	uv run --locked mypy src/account_connections
	uv run --locked pytest -q
	git diff --check
