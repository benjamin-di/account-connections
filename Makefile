.PHONY: check check-browser
check:
	uv run --locked ruff check .
	uv run --locked ruff format --check .
	uv run --locked mypy src/account_connections
	uv run --locked pytest -q
	git diff --check
	@if [ -f publish/config.toml ] && command -v publish-public >/dev/null 2>&1; then publish-public --check-head .; fi

check-browser:
	uv run --locked --group browser pytest -q tests/test_web_browser.py
