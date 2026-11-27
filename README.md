<div align="center">

# 🛡 Avekshak

### Open-source · Self-hosted · AI-powered Security Operations Center

<br/>

[![CI](https://github.com/avekshak/avekshak/actions/workflows/ci.yml/badge.svg)](https://github.com/avekshak/avekshak/actions/workflows/ci.yml)
[![Test Pipeline](https://github.com/avekshak/avekshak/actions/workflows/test-pipeline.yml/badge.svg)](https://github.com/avekshak/avekshak/actions/workflows/test-pipeline.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/avekshak/avekshak/badge)](https://securityscorecards.dev/viewer/?uri=github.com/avekshak/avekshak)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/avekshak/avekshak)](https://github.com/avekshak/avekshak/releases)
[![Node.js](https://img.shields.io/badge/Node.js-22%2B-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![pnpm](https://img.shields.io/badge/pnpm-12%2B-F69220?logo=pnpm&logoColor=white)](https://pnpm.io)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org)

<br/>

```
  5,000 raw alerts / day
          │
          ▼
       Avekshak   ──→   12 incidents   ──→   AI verdict   ──→   You decide
     
```

> **The AI proposes. You decide. Nothing acts without your approval.**

<br/>

</div>

---

## Why Avekshak?

Modern security tools generate thousands of alerts every day. A mid-sized organisation produces **11,000+ alerts daily** — fewer than 1% represent a real threat. Security teams get overwhelmed, real attacks get buried, and breaches take an average of months to discover.

Avekshak does the first pass automatically, entirely on your own infrastructure:

| Step | What happens |
|:---:|---|
| 🔌 **Collect** | Pull raw events from Syslog, Wazuh, and AWS CloudTrail connectors |
| 🔍 **Detect** | Run every event through a YAML-driven rule engine (11 built-in rules) |
| 🔗 **Correlate** | Group related alerts into a single, actionable incident |
| 🤖 **Investigate** | Local LLM agent triages each incident — no data leaves your machine |
| 📋 **Record** | Every query, score, and piece of evidence goes into an immutable audit ledger |
| 🧑‍💻 **Decide** | You approve or reject in a web console before anything acts |

---

## Core Principles

```
┌─────────────────────────────────────────────────────────────────────┐
│  🔒  Human in the loop     │  AI proposes, humans decide.           │
│                            │  Nothing acts without approval.        │
├─────────────────────────────────────────────────────────────────────┤
│  🏠  Fully self-hosted     │  AI runs locally via Ollama.           │
│                            │  No data, prompts, or results leave    │
│                            │  your machine.                         │
├─────────────────────────────────────────────────────────────────────┤
│  💸  No API keys needed    │  No per-query fees. No external AI     │
│                            │  dependencies in production.           │
├─────────────────────────────────────────────────────────────────────┤
│  🔎  Transparent reasoning │  Every agent step is recorded,         │
│                            │  timestamped, and auditable.           │
├─────────────────────────────────────────────────────────────────────┤
│  📖  Open source           │  MIT licensed. Fork it, modify it,     │
│                            │  self-host it.                         │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Architecture

```
                        ╔══════════════════════════════════════════╗
  External sources      ║               Avekshak                   ║
  ─────────────────     ║                                          ║
                        ║  ┌──────────┐       ┌──────────┐         ║
  Syslog (UDP/TCP) ────────▶          │       │          │         ║
  Wazuh JSON       ────────▶  ingest  ├──────▶  fusion   │         ║
  AWS CloudTrail   ────────▶          │       │          │         ║
                        ║  └──────────┘       └────┬─────┘         ║
                        ║  Normalise events    YAML rule engine    ║
                        ║                          │ alerts        ║
                        ║                     ┌────▼──────┐        ║
                        ║                     │correlation│        ║
                        ║                     └────┬──────┘        ║
                        ║                     Group → incident     ║
                        ║                          │               ║
                        ║                     ┌────▼──────┐        ║
                        ║                     │   agent   │        ║
                        ║                     │ LLM triage│        ║
                        ║                     │  + ledger │        ║
                        ║                     └────┬──────┘        ║
                        ║                          │               ║
                        ║          ┌───────────────▼──────────┐    ║
                        ║          │        PostgreSQL        │    ║
                        ║          └──────────────────────────┘    ║
                        ║                                          ║
                        ║  ┌───────────┐       ┌────────────────┐  ║
                        ║  │    api    │◀──────│   web console  │  ║
                        ║  │  Fastify  │       │  React + Vite  │  ║
                        ║  └───────────┘       └────────────────┘  ║
                        ║                                          ║
                        ║  Redis (BullMQ queues between services)  ║
                        ╚══════════════════════════════════════════╝
```

### Services

| Service | Package | Responsibility |
|---|---|---|
| **ingest** | `@avekshak/ingest` | Listens on Syslog UDP/TCP, Wazuh webhook, and AWS CloudTrail. Normalises every raw event into a common schema and enqueues it for detection. |
| **fusion** | `@avekshak/fusion` | YAML rule engine — evaluates each normalised event, fires alerts on rule matches, and maintains sliding-window counters for threshold-based rules (e.g. brute-force). |
| **correlation** | `@avekshak/correlation` | Groups related alerts into a single incident using configurable correlation keys (source IP, actor, rule family). Prevents alert duplication. |
| **agent** | `@avekshak/agent` | LLM-powered triage worker. Investigates each incident, writes an append-only audit ledger, and produces a structured verdict with confidence score and recommended action. |
| **api** | `@avekshak/api` | Fastify REST API — exposes the incident queue, full incident detail, and the approve/reject human gate. |
| **web** | `@avekshak/web` | React dashboard — lists the triage queue, shows AI verdict + evidence, and lets an operator approve or reject. |

### Shared Packages

| Package | Responsibility |
|---|---|
| `@avekshak/db` | Drizzle ORM schema + migration runner for PostgreSQL |
| `@avekshak/schema` | Shared TypeScript types used across all services |
| `@avekshak/queue` | Typed BullMQ queue wrapper — shared between producers and consumers |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js 22 + TypeScript 5 |
| HTTP | Fastify |
| Database | PostgreSQL 16 + Drizzle ORM |
| Queues | BullMQ + Redis 7 |
| AI — local | Ollama · `llama3.2:3b` (default, no API key) |
| AI — hosted | Anthropic Claude (opt-in via `LLM_PROVIDER=claude`) |
| Frontend | React 18 + Vite 5 |
| Monorepo | pnpm 12 workspaces |
| Testing | Vitest + `@vitest/coverage-v8` |
| CI/CD | GitHub Actions |
| Infra | Docker Compose |

---

## Quick Start

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | latest | For Postgres, Redis, Ollama |
| [Ollama](https://ollama.com) | latest | Local LLM runtime |
| [Node.js](https://nodejs.org) | 22+ | — |
| [pnpm](https://pnpm.io) | 12+ | `npm install -g pnpm` |

### 1 — Pull the LLM model

```bash
ollama pull llama3.2:3b
```

### 2 — Clone and install

```bash
git clone https://github.com/avekshak/avekshak.git
cd avekshak
pnpm install
```

### 3 — Configure environment

```bash
cp .env.example .env
```

<details>
<summary>Default <code>.env</code> values</summary>

```env
POSTGRES_URL=postgres://avekshak:avekshak@localhost:5433/avekshak
REDIS_URL=redis://localhost:6379
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2:3b
API_PORT=8000
SYSLOG_UDP_PORT=5140
SYSLOG_TCP_PORT=6010
LLM_PROVIDER=ollama          # set to "claude" to use Anthropic Claude instead
```

</details>

### 4 — Start infrastructure

```bash
docker compose up -d        # starts Postgres (5433), Redis (6379), Ollama (11434)
```

### 5 — Build and migrate

```bash
pnpm build
pnpm --filter @avekshak/db --env-file=.env migrate
```

### 6 — Start all services

Open five terminal tabs and run one per tab:

```bash
pnpm --filter @avekshak/api         --env-file=.env dev
pnpm --filter @avekshak/fusion      --env-file=.env start
pnpm --filter @avekshak/correlation --env-file=.env start
pnpm --filter @avekshak/agent       --env-file=.env start
pnpm --filter @avekshak/web         --env-file=.env dev
```

### 7 — Open the dashboard

```
http://localhost:5173
```

### 8 — Seed demo data _(optional)_

```bash
pnpm --filter @avekshak/web --env-file=.env seed
```

This creates two pre-triaged incidents — one critical (data exfiltration, severity 90) and one benign (root login at 4 a.m., severity 30) — so you can explore the full approve/reject flow immediately.

---

## Sending Events

Once all services are running, pipe events into Avekshak via any connector:

### Syslog

```bash
# Start the Syslog listener (UDP + TCP)
pnpm --filter @avekshak/ingest --env-file=.env syslog

# Send a test event (UDP)
echo "<34>1 $(date -u +%FT%TZ) host.example sshd 1234 - - Failed password for root" \
  | nc -u -w1 127.0.0.1 5140
```

### Wazuh

```bash
pnpm --filter @avekshak/ingest --env-file=.env wazuh
```

### AWS CloudTrail

```bash
pnpm --filter @avekshak/ingest --env-file=.env aws
```

---

## Detection Rules

Avekshak ships **11 built-in YAML detection rules** in `detections/rules.yaml`. Each rule matches a single normalised event when all `when` conditions hold.

| Rule ID | Title | Severity |
|---|---|:---:|
| `auth-failed-login` | Failed authentication | 40 |
| `auth-root-login-success` | Successful root/admin login | 60 |
| `aws-console-login-root` | AWS console login by privileged user | 55 |
| `aws-access-denied` | AWS API call denied (possible probing) | 45 |
| `cloud-exfiltration-finding` | Cloud data exfiltration finding | **85** |
| `cloud-unauthorized-access` | Cloud unauthorized access finding | **80** |
| `known-bad-ip` | Activity from a known-bad IP | **75** |
| `high-severity-source` | High-severity event from source | 65 |
| `file-integrity-change` | File integrity / syscheck change | 35 |
| `impossible-travel-foreign` | Privileged login from a foreign location | 70 |
| `brute-force-logins` | Brute-force auth — 5 failures / 5 min from one IP | 70 |

You can add custom rules by editing `detections/rules.yaml` — no code changes needed.

---

## LLM Providers

The agent service supports two interchangeable backends, configured via `LLM_PROVIDER` in `.env`:

| Provider | `LLM_PROVIDER` | Notes |
|---|---|---|
| **Ollama** (default) | `ollama` | Fully local — no data leaves your machine. Requires Ollama + `llama3.2:3b`. |
| **Anthropic Claude** | `claude` | Hosted — requires `ANTHROPIC_API_KEY` in `.env`. Better reasoning quality. |

```env
# For Ollama (default — no API key needed)
LLM_PROVIDER=ollama

# For Claude (requires API key)
LLM_PROVIDER=claude
ANTHROPIC_API_KEY=sk-ant-...
```

---

## API Reference

Base URL: `http://localhost:8000`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health — checks Postgres and Redis connectivity |
| `GET` | `/incidents` | List all incidents, sorted by severity (highest first) |
| `GET` | `/incidents/:id` | Full incident detail — alerts, events, AI verdict, audit ledger |
| `POST` | `/incidents/:id/approve` | Approve the AI recommendation; triggers a dry-run response |
| `POST` | `/incidents/:id/reject` | Reject the AI recommendation and record the decision |

<details>
<summary>Example requests</summary>

```bash
# Health check
curl http://localhost:8000/health

# List incidents
curl http://localhost:8000/incidents

# Get incident detail
curl http://localhost:8000/incidents/<id>

# Approve
curl -X POST http://localhost:8000/incidents/<id>/approve \
  -H "Content-Type: application/json" -d '{}'

# Reject
curl -X POST http://localhost:8000/incidents/<id>/reject \
  -H "Content-Type: application/json" -d '{}'
```

</details>

---

## Project Structure

```
avekshak/
├── services/
│   ├── ingest/            # Syslog / Wazuh / CloudTrail connectors
│   ├── fusion/            # YAML detection rule engine
│   ├── correlation/       # Alert → Incident grouping
│   ├── agent/             # LLM triage worker + audit ledger
│   │   └── src/llm/       # Pluggable LLM backends (Ollama, Claude)
│   └── api/               # Fastify REST API
├── apps/
│   └── web/               # React incident console
│       └── scripts/       # seed-demo.ts — demo data seeder
├── packages/
│   ├── db/                # Drizzle ORM schema + migrations
│   ├── schema/            # Shared TypeScript types
│   └── queue/             # BullMQ typed queue wrapper
├── detections/
│   └── rules.yaml         # YAML detection rules (add your own here)
├── .github/
│   ├── workflows/         # CI/CD pipelines
│   └── ISSUE_TEMPLATE/    # Bug report + feature request forms
├── docker-compose.yml     # Postgres, Redis, Ollama
├── .env.example
└── pnpm-workspace.yaml
```

---

## Development

### Run tests

```bash
pnpm test                                     # all packages
pnpm --filter @avekshak/api test              # one service
pnpm --filter @avekshak/api test --coverage   # with coverage report
```

### Type-check all packages

```bash
pnpm typecheck
```

### Build all packages

```bash
pnpm build
```

---

## CI / CD

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | Push to `main` or `test` | Build all packages |
| `test-pipeline.yml` | PR → `test` branch | Build + run all tests with Postgres and Redis |
| `require-tests.yml` | PR → `test` or `main` | Fails if `.ts` source files changed without a `.test.ts` file |
| `promote-test-to-main.yml` | Push to `test` | Auto-promotes `test` → `main` after tests pass |
| `sync-main-to-test.yml` | Push to `main` | Keeps `test` in sync with `main` |

### Branch workflow

```
  your-feature-branch
         │
         │  pull request
         ▼
        test  ──── (auto-promote on green) ────▶  main
```

> **PRs must target `test`, not `main` directly.**
> Coverage thresholds are enforced per service — the pipeline blocks merges below threshold.

---

## Contributing

We welcome contributions of all kinds. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR.

**Quick checklist:**

- [ ] Fork the repo and create a branch (`feat/your-feature-name`)
- [ ] PR targets the **`test`** branch — not `main`
- [ ] Tests added or updated for your changes
- [ ] All tests pass locally: `pnpm test`
- [ ] Agree to the [CLA](CLA.md)
- [ ] Follow the [Code of Conduct](CODE_OF_CONDUCT.md)
- [ ] Report security issues privately per [SECURITY.md](SECURITY.md)

Browse issues labelled [`good first issue`](https://github.com/avekshak/avekshak/issues?q=is%3Aopen+label%3A%22good+first+issue%22) for a starting point.

---

## Team

| Name | GitHub | Role |
|---|---|---|
| Kunal Kumar Dey | [@kunal2303](https://github.com/kunal2303) | Maintainer |
| Anurag Shrivastava | — | Contributor |
| Bhumi Budhiraja | — | Contributor |
| Urooj Fatima | [@urooj-bits](https://github.com/urooj-bits) | Contributor |

---

## License

[MIT](LICENSE) — free to use, self-host, fork, and modify.

---

<div align="center">

*Built with the belief that security tooling should be transparent, auditable, and in the hands of the people who need it most.*

<br/>

⭐ **If Avekshak is useful to you, consider starring the repo.**

</div>
