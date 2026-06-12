.PHONY: install install-dev test lint format scan study clean

install:
	pip install -e .

install-dev:
	pip install -e ".[dev,experiments]"

test:
	pytest tests/ -v

lint:
	ruff check .

format:
	ruff format .

scan:
	vibeguard scan ./security

study:
	python -m experiments.run_study --out-dir results

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
