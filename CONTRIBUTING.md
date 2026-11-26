# Contributing to Avekshak

Thank you for your interest in contributing! This document explains how to get started.

## Before You Start

By submitting a pull request, you agree to the [Contributor License Agreement](CLA.md).
Please read it before contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/avekshak.git`
3. Install dependencies: `pnpm install`
4. Create a branch: `git checkout -b feat/your-feature-name`

## Development Setup

**Requirements:**
- Node.js 22+
- Docker Desktop (for PostgreSQL and Redis)
- Ollama with `llama3.2:3b` pulled (`ollama pull llama3.2:3b`)
- pnpm 12+ (`npm install -g pnpm`)
- 8GB RAM minimum (16GB recommended)

**Start infrastructure:**
```bash
docker compose up -d        # PostgreSQL and Redis only
```

**Run a service:**
```bash
pnpm --filter @avekshak/api dev        # API service
pnpm --filter @avekshak/agent dev      # Agent service
pnpm --filter @avekshak/ingest syslog  # Syslog connector
```

**Build all packages:**
```bash
pnpm build
```

**Run all tests:**
```bash
pnpm test
```

## Project Structure

```
avekshak/
├── services/
│   ├── ingest/        # Connector pollers (CloudTrail, Wazuh, Syslog)
│   ├── fusion/        # Detection engine + alert promotion
│   ├── correlation/   # Groups alerts into incidents
│   ├── agent/         # LLM triage + ledger writer
│   └── api/           # REST API
├── apps/
│   └── web/           # React dashboard
├── packages/
│   ├── schema/        # Shared types
│   ├── queue/         # BullMQ wrapper
│   └── db/            # Database client + migrations
└── detections/        # YAML detection rules
```

## Types of Contributions

- **Bug fixes** — open an issue first to describe the bug
- **Detection rules** — add YAML rules under `detections/`
- **Connectors** — new data source adapters under `services/ingest/src/connectors/`
- **Documentation** — always welcome

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Include tests for any behavioural changes
- Update documentation if you change an interface
- Run `pnpm test` before submitting
- PRs must target the `test` branch, not `main`

## Commit Message Format

```
type(scope): short description

feat(correlation): add time-window grouping algorithm
fix(agent): handle malformed LLM JSON response
docs(readme): add Ollama setup instructions
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`

## Good First Issues

Look for issues labeled `good first issue` — these are scoped to a single connector,
rule, or documentation improvement with clear expected output.

## Questions

Open a GitHub Discussion for design questions or ideas before you start building.
