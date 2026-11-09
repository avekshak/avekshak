# Aavekshak

**Open-source AI Security Operations Center. Runs on your own machine.**

Aavekshak reads every security alert for you, groups related ones into a single incident, investigates it with a local AI agent, and shows you its work — so the one attack that matters never gets buried under five thousand that don't.

```
5,000 alerts/day  →  Aavekshak  →  12 incidents  →  AI verdict  →  You decide
```

---

## The Problem

Modern security tools generate thousands of alerts every day. A mid-sized organization produces 11,000+ alerts daily, of which less than 1% represent a real threat. Security teams are overwhelmed — alerts get muted, attackers go undetected, and breaches take an average of 277 days to discover.

## The Solution

Aavekshak does the first pass automatically:

1. **Collects** events from cloud accounts, servers, and security tools
2. **Detects** suspicious patterns using a focused rule engine
3. **Correlates** related alerts into a single incident
4. **Investigates** each incident with a local AI agent
5. **Records** every query and piece of evidence in an investigation ledger
6. **Waits** for a human to approve before any action is taken

## Key Principles

- **Human in the loop** — the AI proposes, a human decides. Nothing acts without approval.
- **Fully self-hosted** — the AI model runs locally via Ollama. No data leaves your machine.
- **No API keys required** — no per-query fees, no external dependencies.
- **Transparent reasoning** — every step the AI took is recorded and auditable.

## Stack

| Layer      | Choice                         |
|------------|--------------------------------|
| Backend    | Node.js + TypeScript + Fastify |
| Database   | PostgreSQL                     |
| Queue      | BullMQ + Redis                 |
| AI Model   | Ollama · llama3.2:3b           |
| Frontend   | React + Vite                   |
| Infra      | Docker Compose                 |

## Quick Start

```bash
# Requirements: Docker Desktop, Ollama

ollama pull llama3.2:3b

git clone https://github.com/aavekshak/aavekshak.git
cd aavekshak
cp .env.example .env
docker compose up
```

Open `http://localhost:3000` to see the dashboard.

## Project Structure

```
aavekshak/
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
│   └── detections/    # YAML detection rules
└── deployments/
    └── demo/          # Docker Compose reference stack
```

## Team

| Name | GitHub |
|------|--------|
| Kunal Kumar Dey | [@kunal2303](https://github.com/kunal2303) |
| Anurag Shrivastava | — |
| Bhumi Budhiraja | — |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributors must agree to the [CLA](CLA.md).

## License

[MIT](LICENSE) — free to use, self-host, and modify.

