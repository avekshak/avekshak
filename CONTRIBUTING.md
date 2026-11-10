# Contributing to Aavekshak

Thank you for your interest in contributing! This document explains how to get started.

## Before You Start

By submitting a pull request, you agree to the [Contributor License Agreement](CLA.md).
Please read it before contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/aavekshak.git`
3. Install dependencies: `npm install`
4. Start the dev stack: `docker compose up -d`
5. Create a branch: `git checkout -b feat/your-feature-name`

## Development Setup

**Requirements:**
- Node.js 20+
- Docker Desktop
- Ollama with `llama3.2:3b` pulled (`ollama pull llama3.2:3b`)
- 8GB RAM minimum (16GB recommended)

**Start everything:**
```bash
docker compose up -d        # PostgreSQL, Redis, Ollama
npm run dev                 # All services in watch mode
```

## Types of Contributions

- **Bug fixes** — open an issue first to describe the bug
- **Detection rules** — add YAML rules under `packages/detections/rules/`
- **Connectors** — new data source adapters under `services/ingest/src/connectors/`
- **Documentation** — always welcome

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Include tests for behavioral changes
- Update documentation if you change an interface
- Add your rule ID if adding a detection rule
- Run `npm test` before submitting

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

Open a GitHub Discussion for design questions or ideas before building.
