.PHONY: check check-browser
check:
	uv run --locked ruff check .
	uv run --locked ruff format --check .
	uv run --locked mypy src/account_connections
	uv run --locked pytest -q
	git diff --check

check-browser:
	uv run --locked --group browser pytest -q tests/test_web_browser.py
