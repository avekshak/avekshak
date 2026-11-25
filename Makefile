.PHONY: up down build logs ps psql redis-cli migrate bootstrap smoke

# --- Infrastructure + pipeline ---
up:
	docker compose up -d --build
	@echo "Waiting for services to become healthy..."
	@sleep 5
	@docker compose ps

down:
	docker compose down

# Build all service images without starting
build:
	docker compose build

logs:
	docker compose logs -f

# Tail logs for a specific service: make logs-api
logs-%:
	docker compose logs -f $*

ps:
	docker compose ps

# --- Convenience shells ---
psql:
	docker exec -it avekshak-postgres psql -U avekshak -d avekshak

redis-cli:
	docker exec -it avekshak-redis redis-cli

# --- Database ---
migrate:
	pnpm --filter @avekshak/db migrate

# --- Bootstrap (run once after first make up) ---
# Runs migrations then verifies the API health endpoint
bootstrap:
	@echo "Running migrations..."
	pnpm --filter @avekshak/db migrate
	@echo "Waiting for API..."
	@sleep 3
	@curl -sf http://localhost:8000/health && echo "\n[bootstrap] API healthy — stack is ready"

# --- End-to-end smoke test ---
smoke:
	pnpm --filter @avekshak/agent tsx --env-file=.env scripts/smoke.ts
