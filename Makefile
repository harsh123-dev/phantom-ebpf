# ============================================================================
# PHANTOM Monorepo Makefile
# ============================================================================
# All targets work from the repository root.
#
# Usage:
#   make install      — Install all Python services + phantom-core in dev mode
#   make lint         — Run ruff on all Python code
#   make typecheck    — Run mypy --strict on all Python service code
#   make test         — Run pytest across all Python services and phantom-core
#   make format       — Auto-format all Python code with ruff
#   make build        — Build Python wheel artifacts for all services
#   make docker-up    — Start local infrastructure (PostgreSQL, Redis, etc.)
#   make docker-down  — Stop and remove local infrastructure containers
# ============================================================================

.PHONY: install lint typecheck test format build docker-up docker-down migrate-local help

# ---------------------------------------------------------------------------
# Service directories
# ---------------------------------------------------------------------------
PYTHON_SERVICES := services/sbom-service services/causal-engine services/api-gateway services/report-generator
PHANTOM_CORE    := libs/phantom-core

# ---------------------------------------------------------------------------
# install — Install all Python services and phantom-core in editable dev mode
# ---------------------------------------------------------------------------
install:
	pip install -e "$(PHANTOM_CORE)[dev]"
	@for svc in $(PYTHON_SERVICES); do \
		echo ">>> Installing $$svc"; \
		pip install -e "$$svc[dev]"; \
	done

# ---------------------------------------------------------------------------
# lint — Run ruff check on all Python code
# ---------------------------------------------------------------------------
lint:
	ruff check $(PHANTOM_CORE)/phantom_core/ $(PHANTOM_CORE)/tests/
	@for svc in $(PYTHON_SERVICES); do \
		echo ">>> Linting $$svc"; \
		ruff check "$$svc/app/" "$$svc/tests/"; \
	done

# ---------------------------------------------------------------------------
# typecheck — Run mypy --strict on all Python services and phantom-core
# ---------------------------------------------------------------------------
typecheck:
	mypy --strict $(PHANTOM_CORE)/phantom_core/
	@for svc in $(PYTHON_SERVICES); do \
		echo ">>> Type-checking $$svc"; \
		mypy --strict "$$svc/app/"; \
	done

# ---------------------------------------------------------------------------
# test — Run pytest across all test suites
# ---------------------------------------------------------------------------
test:
	pytest $(PHANTOM_CORE)/tests/ -v --tb=short
	@for svc in $(PYTHON_SERVICES); do \
		echo ">>> Testing $$svc"; \
		pytest "$$svc/tests/" -v --tb=short; \
	done

# ---------------------------------------------------------------------------
# format — Auto-format all Python code
# ---------------------------------------------------------------------------
format:
	ruff format $(PHANTOM_CORE)/phantom_core/ $(PHANTOM_CORE)/tests/
	@for svc in $(PYTHON_SERVICES); do \
		echo ">>> Formatting $$svc"; \
		ruff format "$$svc/app/" "$$svc/tests/"; \
	done

# ---------------------------------------------------------------------------
# build — Build Python wheel artifacts
# ---------------------------------------------------------------------------
build:
	cd $(PHANTOM_CORE) && python -m build --wheel
	@for svc in $(PYTHON_SERVICES); do \
		echo ">>> Building $$svc"; \
		cd "$$svc" && python -m build --wheel && cd ../..; \
	done

# ---------------------------------------------------------------------------
# docker-up — Start local infrastructure
# ---------------------------------------------------------------------------
docker-up:
	docker compose up -d

# ---------------------------------------------------------------------------
# docker-down — Stop and remove local infrastructure containers
# ---------------------------------------------------------------------------
docker-down:
	docker compose down

# ---------------------------------------------------------------------------
# migrate-local — Apply all SQL migrations to the local docker-compose PostgreSQL
#
# Applies migrations for each service in dependency order:
#   1. sbom-service (001_initial.sql, 002_add_missing_fields.sql)
#   2. api-gateway  (001..006, in lexicographic order)
#
# Prerequisites:
#   - docker compose up -d must have been run first
#   - psql must be available on PATH  (brew install postgresql, apt install postgresql-client)
#
# Usage:
#   make migrate-local
#   make migrate-local PGHOST=localhost PGPORT=5433  # override defaults
# ---------------------------------------------------------------------------
PGHOST   ?= localhost
PGPORT   ?= 5432
PGUSER   ?= phantom
PGPASS   ?= phantom_dev_password
PGDB     ?= phantom

PSQLCMD  := PGPASSWORD="$(PGPASS)" psql -h $(PGHOST) -p $(PGPORT) -U $(PGUSER) -d $(PGDB)

migrate-local:
	@echo ">>> Waiting for PostgreSQL to be ready..."
	@until $(PSQLCMD) -c "SELECT 1" > /dev/null 2>&1; do sleep 1; done
	@echo ">>> Applying sbom-service migrations..."
	@for f in $(shell ls services/sbom-service/app/infrastructure/postgres/migrations/*.sql | sort); do \
		echo "  Applying $$f"; \
		$(PSQLCMD) -f "$$f" || exit 1; \
	done
	@echo ">>> Applying api-gateway migrations..."
	@for f in $(shell ls services/api-gateway/app/infrastructure/migrations/*.sql | sort); do \
		echo "  Applying $$f"; \
		$(PSQLCMD) -f "$$f" || exit 1; \
	done
	@echo ">>> All migrations applied successfully."
# ---------------------------------------------------------------------------
# help — Show available targets
# ---------------------------------------------------------------------------
help:
	@echo "Available targets:"
	@echo "  make install      Install all Python services + phantom-core in dev mode"
	@echo "  make lint         Run ruff on all Python code"
	@echo "  make typecheck    Run mypy --strict on all Python service code"
	@echo "  make test         Run pytest across all Python services and phantom-core"
	@echo "  make format       Auto-format all Python code with ruff"
	@echo "  make build        Build Python wheel artifacts for all services"
	@echo "  make docker-up    Start local infrastructure (PostgreSQL, Redis, etc.)"
	@echo "  make docker-down  Stop and remove local infrastructure containers"
	@echo "  make migrate-local Apply all SQL migrations to local docker-compose PostgreSQL"
