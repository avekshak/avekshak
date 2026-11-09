.PHONY: up down logs ps pull-model psql redis-cli migrate smoke

# --- Infrastructure ---
up:
	docker compose up -d
	@echo "Waiting for services to become healthy..."
	@sleep 3
	@docker compose ps

down:
	docker compose down

logs:
	docker compose logs -f

ps:
	docker compose ps

# Pull the local LLM used by the triage agent (run once after 'make up')
pull-model:
	docker exec sentinel-ollama ollama pull llama3.2:3b

# --- Convenience shells ---
psql:
	docker exec -it sentinel-postgres psql -U sentinel -d sentinel

redis-cli:
	docker exec -it sentinel-redis redis-cli

# --- App (filled in later phases) ---
migrate:
	pnpm --filter @sentinel/db migrate

smoke:
	pnpm tsx scripts/smoke.ts
