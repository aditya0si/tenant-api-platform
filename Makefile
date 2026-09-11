# Local development. CI runs the same steps (see .github/workflows/ci.yml).

PG_URL_OWNER ?= postgres://postgres:postgres@localhost:5432/tenant_platform?sslmode=disable
PG_URL_APP   ?= postgres://app_rw:app_rw@localhost:5432/tenant_platform?sslmode=disable
TEST_DB      ?= tenant_platform_test
TEST_URL_OWNER ?= postgres://postgres:postgres@localhost:5432/$(TEST_DB)?sslmode=disable
TEST_URL_APP   ?= postgres://app_rw:app_rw@localhost:5432/$(TEST_DB)?sslmode=disable

TEST_REDIS_URL ?= redis://localhost:6379/1

export MIGRATE_DATABASE_URL := $(PG_URL_OWNER)
export DATABASE_URL := $(PG_URL_APP)

.PHONY: help tidy fmt vet test test-db build up down logs psql migrate seed sweep testdb-clean

help:
	@echo "make up          start postgres + redis + migrate + api"
	@echo "make test        run the full suite against a throwaway test database"
	@echo "make test-unit   run only tests that need no database"
	@echo "make migrate     apply migrations to the dev database"
	@echo "make sweep       reap expired idempotency keys (owner credentials; see docs/OPERATIONS.md)"
	@echo "make seed        create two demo tenants"
	@echo "make psql        open a psql shell as the application role"

tidy:
	go mod tidy

fmt:
	gofmt -l -w .

vet:
	go vet ./...

build:
	go build ./...

# Unit-only subset: skips the database-backed isolation tests.
test-unit:
	SKIP_DB_TESTS=1 go test -race -count=1 ./...

test: testdb-clean
	$(MAKE) test-with-db

# The test database is created and dropped on every run so a stale schema or a
# leftover fixture can never make a passing suite meaningless.
testdb-clean:
	@psql "$(TEST_URL_OWNER)" -c "SELECT 1" >/dev/null 2>&1 || \
	  psql "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable" \
	       -c "CREATE DATABASE $(TEST_DB)" >/dev/null
	@psql "$(TEST_URL_OWNER)" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;" >/dev/null
	@psql "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable" \
	      -c "DO \$$\$$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='app_rw') THEN CREATE ROLE app_rw LOGIN PASSWORD 'app_rw' NOSUPERUSER NOBYPASSRLS; END IF; END \$$\$$;" >/dev/null

test-with-db:
	TEST_DATABASE_URL="$(TEST_URL_APP)" \
	TEST_MIGRATE_DATABASE_URL="$(TEST_URL_OWNER)" \
	TEST_REDIS_URL="$(TEST_REDIS_URL)" \
	go test -race -count=1 ./...

up:
	docker compose up -d --build
	@echo "waiting for the migration container to finish..."
	@docker compose wait migrate >/dev/null 2>&1 || true
	@docker compose ps

down:
	docker compose down -v

logs:
	docker compose logs -f api

migrate:
	go run ./cmd/migrate up

# Reaping spans tenants, so it needs a role that bypasses row-level security — the same
# owner credentials migrations use. The dev default PG_URL_OWNER is the postgres superuser,
# which satisfies that. See docs/OPERATIONS.md for why the guard exists.
sweep:
	go run ./cmd/migrate sweep

seed:
	go run ./cmd/migrate seed

psql:
	psql "$(PG_URL_APP)"
