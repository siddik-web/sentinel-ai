# Sentinel AI

Open-source AI security response platform: it ingests security alerts, triages them with
governed agents, escalates risky decisions to a human, and records everything in a
tamper-evident audit log.

- **Ingestion** — webhook payloads are normalized to [OCSF](https://schema.ocsf.io/) events and deduplicated.
- **Triage** — deterministic rules set the baseline; an optional LLM adds reasoning and can only *raise* severity or request human review, never lower them.
- **Policy enforcement** — every agent action passes through the Policy Enforcement Point (PEP). High-risk actions always need human approval; operators can add restrictions with a policy file.
- **Human in the loop** — escalations become tickets that an operator approves or rejects from the web console, the API, or the CLI.
- **Audit** — a SHA-256 hash-chained log, written to SQLite before each action is taken and verifiable offline.

Design documents: [charter](docs/PROJECT_CHARTER.md) · [architecture](architecture/ARCHITECTURE.md) ·
[agents](agents/AGENTS.md) · [security](docs/SECURITY.md) · [engineering](docs/ENGINEERING.md).

> **Status: v0.1, pre-production.** The response adapters (`ISOLATE_HOST`, `TERMINATE_PROCESS`,
> `REVOKE_CREDENTIALS`, `BLOCK_IP`) are reference implementations that record the action but do
> **not** call a real EDR, identity provider, or firewall. See [Limitations](#limitations).

## Quickstart

Requires Python 3.11+.

```bash
git clone https://github.com/siddik-web/sentinel-ai.git
cd sentinel-ai
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

sentinel-ai serve            # http://127.0.0.1:8000
```

In a second terminal, send an alert and act on it:

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/webhook \
  -H 'Content-Type: application/json' \
  -d '{"class_uid": 2001, "activity_id": 1, "severity_id": 5,
       "title": "Ransomware Activity Detected", "analytic_name": "EDR-BEHAVIORAL",
       "confidence_score": 0.98, "device_hostname": "wks-fin-07"}'

sentinel-ai hitl list
sentinel-ai hitl approve '<ticket id from the list>'
sentinel-ai audit verify
```

Or open <http://127.0.0.1:8000/> and approve or reject the ticket in the console.

### Docker

```bash
docker compose up --build    # console on http://127.0.0.1:8000
```

The compose file publishes the port on loopback only and keeps the database in a named volume.

## Configuration

All settings are environment variables.

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_HOST` | `127.0.0.1` | Bind address |
| `SENTINEL_PORT` | `8000` | Bind port |
| `SENTINEL_DB_PATH` | `sentinel_ai.db` | SQLite database (audit log, tickets, workflow state) |
| `SENTINEL_API_TOKEN` | unset | When set, `/api/*` requires `Authorization: Bearer <token>` |
| `SENTINEL_POLICY_FILE` | unset | JSON policy file (see below) |
| `SENTINEL_HITL_WEBHOOK_URL` | unset | Receives a POST for every new escalation ticket |
| `SENTINEL_LLM_PROVIDER` | `none` | `none`, `openai` (any OpenAI-compatible API), `ollama`, `lmstudio`, `mock` |
| `SENTINEL_LLM_MODEL` | provider default | Model name |
| `SENTINEL_LLM_API_BASE` | provider default | API base URL |
| `SENTINEL_LLM_API_KEY` | unset | Required for `openai` |
| `SENTINEL_LOG_LEVEL` | `INFO` | Log level (logs are JSON lines on stderr) |

**Set `SENTINEL_API_TOKEN` before binding to anything other than loopback.** Without it the
API — including ticket approval — accepts unauthenticated requests; the server logs a warning
when started that way. `/`, `/healthz` and `/metrics` are never authenticated.

### Policy file

Built-in policy always applies: only known actions are allowed, and the four response
actions require human approval. A policy file can add restrictions but cannot relax those.

```bash
sentinel-ai policy validate config/policy.example.json
SENTINEL_POLICY_FILE=config/policy.example.json sentinel-ai serve
```

| Key | Meaning |
|---|---|
| `denied_actions` | Actions no agent may perform |
| `hitl_required_actions` | Additional actions needing human approval |
| `trusted_ips` | IPs that may never be blocked |
| `agent_allowed_actions` | Per-agent capability grants: `{agent_id: [actions]}` |

When policy denies an action mid-triage, the workflow halts, the denial and its rule are
audited, and a `MANUAL_REVIEW` ticket is raised.

## HTTP API

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/webhook` | Ingest an alert (JSON object with `class_uid`; see below) |
| `GET` | `/api/v1/hitl[?status=PENDING]` | List escalation tickets |
| `POST` | `/api/v1/hitl/approve` | `{"ticket_id", "approver"}` — approve and execute the action |
| `POST` | `/api/v1/hitl/reject` | `{"ticket_id", "approver"}` — dismiss without action |
| `GET` | `/api/v1/workflows[?limit=N]` | Recent workflows and their state |
| `GET` | `/api/v1/audit[?limit=N]` | Most recent audit entries |
| `GET` | `/api/v1/audit/verify` | Verify the persisted hash chain |
| `GET` | `/api/v1/stats` | Counters as JSON |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/healthz` | Liveness probe |

Supported event classes (`class_uid`): `3002` authentication, `2001` finding, `1007` process
activity, `4001` network activity. Field definitions are in
[`core/ocsf/models.py`](src/sentinel_ai/core/ocsf/models.py); example payloads are in
[`tests/fixtures/alert_corpus/`](tests/fixtures/alert_corpus).

## CLI

```
sentinel-ai serve [--host H] [--port P]     run the server
sentinel-ai ingest FILE                     ingest one alert from a JSON file
sentinel-ai replay FILE                     run an alert through the agents without persisting anything
sentinel-ai hitl list|approve|reject        manage escalation tickets
sentinel-ai workflows                       list recent workflows
sentinel-ai audit verify|export [-o FILE]   verify the hash chain / export it as JSON Lines
sentinel-ai policy validate FILE            check a policy file
sentinel-ai evaluate DIR                    run the behavioral evaluation corpus
```

`--db PATH` selects the database for commands that use one.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
sentinel-ai evaluate tests/fixtures/alert_corpus
```

See [docs/SETUP.md](docs/SETUP.md) and [docs/CONVENTIONS.md](docs/CONVENTIONS.md).

## Limitations

- **Response adapters are simulated.** Approving a ticket records a `[SIMULATED]` result; wire
  `response/edr.py` and `response/identity.py` to real vendor APIs before relying on them.
- **The forensic agent is a stub.** It records a policy-checked enrichment step but performs no
  real threat-intelligence or asset lookups.
- **The evaluation corpus is synthetic.** Its 22 scenarios are regression tests for the triage
  rules, not analyst-verified ground truth.
- **Authentication is a single shared token.** There are no per-user accounts or roles; the
  `approver` recorded on a decision is self-declared.
- **Single node.** State lives in one SQLite file and alerts are processed one at a time.
- **No license file yet.** The project describes itself as open source, but no license has
  been chosen.
