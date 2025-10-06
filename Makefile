.PHONY: help install install-dev test coverage lint format clean docker-build docker-run docs pre-commit-install pre-commit-run

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	uv pip install -r requirements.txt

install-dev: ## Install development dependencies
	uv pip install -r requirements.txt
	uv pip install -e ".[dev]"
	pre-commit install

test: ## Run tests
	pytest

test-verbose: ## Run tests with verbose output
	pytest -vv

test-specific: ## Run specific test file (usage: make test-specific TEST=tests/test_core/test_client.py)
	pytest $(TEST) -vv

coverage: ## Run tests with coverage report
	pytest --cov=src/opnsense_mcp --cov-report=html --cov-report=term-missing
	@echo "Coverage report generated in htmlcov/index.html"

coverage-xml: ## Generate XML coverage report for CI
	pytest --cov=src/opnsense_mcp --cov-report=xml

lint: ## Run linting checks (ruff + black check + mypy)
	ruff check src/ tests/
	black --check src/ tests/
	mypy src/

format: ## Format code with black and ruff
	black src/ tests/
	ruff check --fix src/ tests/

pre-commit-install: ## Install pre-commit hooks
	pre-commit install

pre-commit-run: ## Run pre-commit hooks on all files
	pre-commit run --all-files

clean: ## Clean up generated files
	rm -rf build/ dist/ *.egg-info htmlcov/ .coverage coverage.xml
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

docker-build: ## Build Docker image
	docker build -t opnsense-mcp-server:latest .

docker-run: ## Run Docker container
	docker-compose up

docker-stop: ## Stop Docker container
	docker-compose down

docker-logs: ## Show Docker container logs
	docker-compose logs -f

docs: ## Generate documentation
	@echo "Documentation generation not yet configured"
	@echo "Run 'python -m pydoc -b' for built-in documentation"

release-check: ## Check if ready for release (tests, lint, security)
	@echo "Running pre-release checks..."
	make lint
	make test
	make coverage
	@echo "✅ All checks passed!"

security-scan: ## Run security scans
	pip-audit
	bandit -r src/ -ll

benchmark: ## Run performance benchmarks
	@echo "Benchmarking not yet configured"

version: ## Show current version
	@python -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])"

setup-dev: install-dev pre-commit-install ## Complete development environment setup
	@echo "✅ Development environment setup complete!"
	@echo "Run 'make test' to verify installation"
