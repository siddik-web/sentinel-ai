# Architecture — Sentinel AI

> **Document class:** System architecture reference
> **Status:** Active
> **Derived from:** `PROJECT_CHARTER.md` §10 (EP1–EP8); `docs/SECURITY.md` §2.4 (Trust Boundaries)
> **Depends on:** `ADR-001` (OCSF event schema); `agents/AGENTS.md` (agent role contracts)
> **Audience:** Software Architects, Platform Engineers, Security Engineers, Integration Authors

---

## Table of Contents

1. [Purpose and Scope](#1-purpose-and-scope)
2. [Architectural Goals and Constraints](#2-architectural-goals-and-constraints)
3. [System Overview](#3-system-overview)
4. [Component Descriptions](#4-component-descriptions)
5. [Data Flow](#5-data-flow)
6. [Trust Boundaries and Security Boundaries](#6-trust-boundaries-and-security-boundaries)
7. [Event Schema](#7-event-schema)
8. [State Model](#8-state-model)
9. [Deployment Architecture](#9-deployment-architecture)
10. [Cross-Cutting Concerns](#10-cross-cutting-concerns)
11. [Architectural Decision Index](#11-architectural-decision-index)

---

## 1. Purpose and Scope

This document is the authoritative reference for the Sentinel AI system architecture. It describes how the platform's components are structured, how they communicate, how state flows through the system, and why key structural decisions were made.

**This document governs:** component decomposition, inter-component interfaces, the event schema contract, the workflow state model, deployment topology, and the relationship between the architecture and the security trust boundary model.

**This document does not govern:** engineering process (`docs/ENGINEERING.md`), platform security controls (`docs/SECURITY.md`), agent role definitions and capability sets (`agents/AGENTS.md`), AI governance and evaluation methodology (`.ai/AI_PRINCIPLES.md`), or the strategic product direction (`docs/VISION.md`).

**Relationship to ADRs:** Architectural decisions with meaningful alternatives are recorded in `.ai/decisions/`. This document describes the architecture that resulted from those decisions. Where a decision is non-obvious, a reference to the relevant ADR is included.

---

## 2. Architectural Goals and Constraints

The architecture is shaped by five properties that must hold. Any proposed structural change must be evaluated against all five.

### AG1 — Audit completeness is unconditional

Every agent action, tool invocation, policy evaluation, and state transition must be captured in the audit log with no gaps. The audit log is the ground truth for what the system did and why. Architecture that optimizes for throughput at the cost of audit completeness is not acceptable. See `docs/SECURITY.md` §5.2.

### AG2 — Governance is enforced at the boundary, not assumed in the agent

Agents do not self-govern. The policy engine evaluates every agent action before execution. An agent cannot reach an external system, invoke a tool, or authorize a response action without passing through an enforcement point. The architecture must make this boundary structurally impossible to bypass — not just policy-configured.

### AG3 — Trust boundaries are explicit and enforced at ingress

Every interface where data crosses from a less-trusted to a more-trusted context (the five trust boundaries in `docs/SECURITY.md` §2.4) must be an explicit component boundary with validation logic. Trust is not assumed based on network location, transport security, or the source's reputation.

### AG4 — State is durable and explicit

Agent workflow state, HITL escalation state, and the audit log are written to durable storage before the actions that depend on them are taken. A process failure at any point in the workflow must be recoverable. Implicit state — state inferred from in-memory variables or control flow — is a defect in any component on the critical workflow path.

### AG5 — Component boundaries enable independent testing

The policy engine can be tested without a running agent. The agent reasoning harness can be tested without a live model API. The audit log writer can be tested without a production storage backend. Each component has a stable interface and no hidden dependencies on other components' internals. This directly implements charter EP5 (Testability is an architectural requirement).

---

## 3. System Overview

Sentinel AI is a multi-layer platform. Layers have directional dependencies only — lower layers do not depend on higher layers.

```
┌─────────────────────────────────────────────────────────────────┐
│                       External World                            │
│  Alert sources · Response targets · Model APIs · Enrichment     │
└──────────────┬──────────────────────────────┬───────────────────┘
               │ inbound events               │ outbound actions
               ▼                              ▼
┌──────────────────────────────────────────────────────────────── ┐
│                    Integration Layer                            │
│  Data Source Adapters (in) · Response Adapters (out)            │
│  OCSF normalization · Schema validation · Credential isolation  │
└──────────────────────────┬──────────────────────────────────────┘
                           │ OCSF events
                           ▼
┌──────────────────────────────────────────────────────────────── ┐
│                    Ingestion Layer                              │
│  Event bus · Deduplication · Alert routing                      │
└──────────────────────────┬──────────────────────────────────────┘
                           │ routed alerts
                           ▼
┌──────────────────────────────────────────────────────────────── ┐
│                    Agent Execution Layer                        │
│  Orchestration Agent · Triage Agent                             │
│  Investigation Agent · Response Agent                           │
│  Tool execution interface · Policy engine enforcement point     │
└──────────────┬───────────────────────────────┬─────────────────┘
               │ state writes / log entries     │ HITL escalations
               ▼                               ▼
┌──────────────────────────────┐  ┌───────────────────────────── ┐
│    Persistence Layer         │  │    HITL Interface             │
│  Workflow state store        │  │  Escalation delivery          │
│  Audit log (append-only)     │  │  Operator decision capture    │
│  Investigation artifact store│  │  Resume signal                │
└──────────────────────────────┘  └────────────────────────────── ┘
```

---

## 4. Component Descriptions

### 4.1 Data Source Adapters

Data source adapters are the platform's inbound integration boundary. Each adapter is responsible for connecting to one external event source (a SIEM, EDR, identity provider, cloud API log stream, or custom webhook), transforming incoming events to OCSF-conformant format, and passing them to the internal event bus.

**Responsibilities:**
- Transport-level connection to the external source
- Mapping source-native event fields to OCSF fields (per `ADR-001`)
- Schema validation of the OCSF output before forwarding
- Rejection and logging of events that fail OCSF validation — malformed events MUST NOT reach the ingestion layer
- Credential isolation: adapter code MUST NOT log, trace, or propagate integration credentials to any downstream component

**Interface:** Adapters emit OCSF-formatted events onto the internal event bus. Each emitted event MUST include the adapter identifier, the source system identifier, and the OCSF schema version.

**Versioning:** Adapters are versioned independently from the platform core. A breaking change to the OCSF schema version targeted by an adapter is a minor version bump for that adapter.

### 4.2 Response Adapters

Response adapters are the outbound integration boundary. Each adapter executes a specific response action against a target system (compute platform, identity provider, firewall, ticketing system, notification channel).

**Responsibilities:**
- Accepting an authorized action request from the Response Agent (via the tool execution interface)
- Executing the action against the target system
- Returning a confirmation or failure result with evidence
- Credential isolation identical to data source adapters

**Constraints:**
- Response adapters MUST NOT initiate actions on their own. Every action is triggered by an authorized call from the Response Agent.
- Response adapters MUST NOT perform enrichment reads. They are write-only at the target system.
- A response adapter that times out MUST return a failure result — it MUST NOT leave the action in an unknown state without notification.

### 4.3 Ingestion Layer

The ingestion layer receives OCSF events from data source adapters, applies platform-level deduplication, and routes alerts to the Orchestration Agent.

**Responsibilities:**
- Receiving OCSF events from adapters
- Deduplication: identical events within a configurable time window are coalesced, not fanned out to multiple agent workflows
- Alert routing: determining which alert classes trigger which agent workflows, based on routing configuration
- Preserving the original event for audit; the ingestion layer MUST NOT mutate the OCSF event received from the adapter

**State:** The ingestion layer is stateless between events. No workflow state is held in this layer. Deduplication state is maintained in the persistence layer.

### 4.4 Policy Engine

The policy engine is the platform's single enforcement point for all agent governance constraints. It evaluates every agent action request (tool call, response authorization, HITL bypass attempt) against the applicable policy file and returns an `allow`, `deny`, or `escalate` decision.

**This is the most security-critical component in the platform.** A bypass of the policy engine is a complete governance failure. Its architecture is held to the strictest isolation and testing requirements.

**Responsibilities:**
- Loading and validating policy files on startup (and on policy update)
- Evaluating action requests against the applicable policy synchronously before execution
- Returning a structured decision: `allow | deny | escalate`, with the policy rule that produced it
- Logging every evaluation decision to the audit log (write-before-evaluate, not write-after)
- Failing closed: an evaluation error or ambiguous result MUST produce `deny`

**Isolation requirements:**
- The policy engine runs as an isolated process or module boundary from agent code. An agent cannot call policy engine internals directly; all calls are through the defined evaluation interface.
- Policy files are loaded from a controlled path. Runtime policy modification by agent code is architecturally prohibited.
- The policy evaluation interface is synchronous on the hot path. Asynchronous evaluation is only acceptable for out-of-band audit purposes, never for the allow/deny gate itself.

### 4.5 Agent Execution Layer

The agent execution layer hosts the four agent role implementations defined in `agents/AGENTS.md`. Each agent role runs in a bounded execution context with access only to the tools declared in its capability set.

**Component structure per agent:**
- **Agent runner:** Manages the agent's execution lifecycle — invocation, timeout, error handling, and result capture
- **Tool interface:** The interface through which agents invoke tools. Every tool call passes through the policy engine before execution
- **Reasoning trace writer:** Writes the structured reasoning trace to the persistence layer as the agent executes (not at completion)
- **Model interface:** The abstraction layer over the model provider API, conformant to the model interface contract in `.ai/AI_PRINCIPLES.md` §8

**Isolation between agent roles:** Each agent role has a distinct capability set. The architecture enforces this at the tool interface layer — an agent instance is initialized with only the tools its role permits. An agent cannot acquire tools by calling another agent or by modifying its own configuration at runtime.

**Hierarchical orchestration:** Only the Orchestration Agent can invoke other agent roles. The Triage, Investigation, and Response Agents are invoked exclusively as delegates of the Orchestration Agent. Peer-to-peer invocation between non-Orchestration roles is architecturally prohibited (`agents/AGENTS.md` §7).

### 4.6 Audit Log

The audit log is an append-only, tamper-evident record of all governed events in the platform. It is not a debugging tool — it is the evidentiary record for post-incident review and compliance audit.

**Structure:**
- JSON Lines format — one event per line
- Cryptographic hash chaining: each entry includes the SHA-256 hash of the previous entry
- Every entry includes: timestamp (ISO8601 with microsecond precision), session ID, workflow ID, agent role, event type, event payload, policy decision (if applicable), and the hash chain value

**Write semantics:**
- **Write-before-act:** The audit log entry for an action MUST be written and durably persisted before the action is executed. A failure between log write and action execution leaves the system in a consistent auditable state. A failure that executes an action without a log entry does not.
- The write path exposes no delete, update, or truncate operation. Append is the only permitted write.
- The audit log writer MUST be a separate module from the agent code. Agents emit structured events to the writer; they do not write to the log directly.

**Integrity verification:**
- The hash chain enables independent offline verification of log integrity
- Any gap in the sequence or hash mismatch is detectable without access to the platform at runtime

### 4.7 Workflow State Store

The workflow state store holds the durable execution state for all in-flight agent workflows. It is the source of truth for: which alerts are being processed, which stage a workflow is at, and whether a workflow is paused pending HITL resolution.

**Requirements:**
- Durable: state MUST survive process restarts
- Consistent: concurrent writes to the same workflow state MUST be serialized
- The state store MUST support workflow state recovery: given a workflow ID, the store returns the full current state sufficient to resume execution from the last durable checkpoint
- State is written at each workflow stage transition before the transition is acted on (write-before-act, same as the audit log)

### 4.8 Investigation Artifact Store

The investigation artifact store holds structured outputs from the Investigation Agent: timelines, entity graphs, evidence references, and response recommendations. Investigation artifacts are Tier 2 (SECURITY SENSITIVE) data.

**Requirements:**
- Write access is restricted to the Investigation Agent via the tool execution interface
- Read access is granted to the Orchestration Agent (to inform HITL escalation content and response authorization), Security Analyst and Auditor roles (for human review), and the replay engine
- Artifacts are immutable once written. An investigation can be extended (new artifact version), but existing artifact versions are not modified

### 4.9 HITL Interface

The HITL interface manages the lifecycle of human escalations: delivery of the escalation payload, capture of the operator decision, and emission of the resume signal to the Orchestration Agent.

**Responsibilities:**
- Accepting escalation requests from the Orchestration Agent
- Delivering the structured escalation payload to the configured notification channel(s)
- Confirming delivery: an undelivered HITL notification is a platform failure, not a degraded state
- Presenting the decision interface to the authorized operator
- Capturing the operator decision and writing it to the workflow state store as a durable event
- Emitting a resume signal to the Orchestration Agent
- Handling HITL timeout per the applicable policy (never default-proceed)

**Delivery guarantee:** HITL notifications use at-least-once delivery with confirmation. A delivery is not considered complete until the notification channel confirms receipt. Delivery failure after the configured retry limit triggers a platform alert to the agent owner.

---

## 5. Data Flow

### 5.1 Alert-to-Triage Flow

```
1. External source emits alert
2. Data source adapter receives alert
3. Adapter maps to OCSF; validates schema
   ├── Validation fails → reject, log, discard
   └── Validation passes →
4. Adapter emits OCSF event to event bus
5. Ingestion layer deduplicates; routes alert
6. Orchestration Agent receives alert; creates workflow; writes initial state
7. Orchestration Agent delegates to Triage Agent
8. Triage Agent requests enrichment tools (policy engine evaluates each request)
9. Policy engine: allow/deny/escalate per policy
   ├── Deny → tool call blocked; denial logged; agent notified
   └── Allow →
10. Tool executes; result validated against output schema; result returned to agent
11. Triage Agent writes reasoning trace entry (per step, not at completion)
12. Triage Agent produces triage output; writes trace ID
13. Orchestration Agent receives triage output
14. Orchestration Agent evaluates confidence and severity:
    ├── Confidence High + action = investigate → delegates to Investigation Agent
    ├── Confidence High + action = respond → evaluates authorization gate
    ├── Confidence Medium/Low or policy requires review → initiates HITL
    └── Verdict = false_positive + confidence High → closes workflow
15. Audit log receives entries throughout (write-before-act at each step)
```

### 5.2 HITL Flow

```
1. Orchestration Agent determines HITL is required
2. Orchestration Agent writes workflow state (status: paused_hitl) to state store
3. HITL interface constructs escalation payload from triage/investigation outputs
4. HITL interface delivers escalation to notification channel
5. Delivery confirmed → workflow remains paused
   Delivery fails (after retries) → platform alert to agent owner; workflow remains paused
6. Operator receives notification; accesses HITL decision interface
7. Operator reviews escalation payload and selects a decision
8. HITL interface writes decision to workflow state store as a durable event
9. HITL interface emits resume signal to Orchestration Agent
10. Orchestration Agent reads the decision; continues workflow per decision
11. All steps are logged to audit log
```

### 5.3 Autonomous Response Flow

```
1. Orchestration Agent confirms all authorization gate conditions (agents/AGENTS.md §6.4)
   ├── Any condition not met → HITL (§5.2)
   └── All conditions met →
2. Orchestration Agent issues authorization token to Response Agent
3. Response Agent validates token (expiry, action match, policy match)
   ├── Invalid → reject; log rejection; escalate to HITL
   └── Valid →
4. Policy engine evaluates the response action request
5. Audit log write for the action (write-before-act)
6. Response Adapter executes the action
7. Response Adapter returns confirmation or failure
8. Response Agent writes execution record (status, evidence, timestamp)
9. Orchestration Agent receives execution record; updates workflow state
```

---

## 6. Trust Boundaries and Security Boundaries

The five trust boundaries defined in `docs/SECURITY.md` §2.4 map to specific component boundaries in the architecture:

| Trust Boundary | Location in architecture | Enforcement mechanism |
|---|---|---|
| **TB1 — Inbound event ingestion** | External source → Data Source Adapter | OCSF schema validation; rejection of non-conformant events |
| **TB2 — Internal event bus** | Data Source Adapter → Ingestion Layer | Adapter identity verification; event bus authentication |
| **TB3 — Agent → tool execution** | Agent → Tool Interface → Policy Engine | Policy engine evaluation; synchronous allow/deny before execution; tool output schema validation |
| **TB4 — Policy engine decision** | Policy Engine → Action execution | Synchronous; fail-closed; write-before-act audit log |
| **TB5 — Outbound integration** | Response Agent → Response Adapter → target | Authorization token validation; action allowlist enforcement; response adapter isolation |

**Model provider API and enrichment APIs** are treated as untrusted external inputs at TB3. The model's response and tool outputs are validated against declared output schemas before being used by agent logic. A model that returns a malformed or out-of-contract response is treated as a tool failure, not a trusted instruction.

---

## 7. Event Schema

### 7.1 Canonical Schema

All events within the platform use OCSF (Open Cybersecurity Schema Framework) as the canonical internal schema. This decision is recorded in `ADR-001`.

**OCSF version:** The targeted OCSF schema version is declared in the platform's version manifest and is a first-class versioned contract. A change to the targeted OCSF version is a minor version bump for all affected adapters and requires a migration guide.

### 7.2 Event Classes

Sentinel AI processes events from the following OCSF classes at MVP scope:

| OCSF Class | Class ID | Primary use |
|---|---|---|
| Authentication | 3002 | Identity-related alerts; login anomalies; privilege escalation indicators |
| Network Activity | 4001 | Network flow anomalies; C2 communication indicators; lateral movement |
| API Activity | 6003 | Cloud API abuse; credential misuse; data exfiltration via API |
| File System Activity | 1001 | Malware indicators; ransomware precursors; unauthorized file access |
| Process Activity | 1007 | Execution anomalies; process injection; suspicious child processes |
| Security Finding | 2001 | Normalized findings from EDR, SIEM, and CSPM tools |

Additional OCSF classes MAY be supported by integrations. Each additional class requires: a declared mapping in the adapter, schema validation coverage in the adapter test suite, and documentation of any fields that cannot be mapped (placed in the OCSF `unmapped` extension namespace).

### 7.3 Extension Fields

Source-specific fields that do not map to an OCSF field MUST be placed in the OCSF `unmapped` extension object. Extension fields:

- MUST NOT be referenced in agent reasoning or policy rules without explicit documentation
- MUST be listed in the adapter's documentation with their type and semantics
- Are Tier 2 (SECURITY SENSITIVE) by default, subject to reclassification per `docs/SECURITY.md` §3

---

## 8. State Model

### 8.1 Workflow States

Every alert that enters the platform has an associated workflow with one of the following states:

| State | Description |
|---|---|
| `received` | Alert received by ingestion layer; awaiting Orchestration Agent assignment |
| `triage_in_progress` | Triage Agent is executing |
| `investigation_in_progress` | Investigation Agent is executing |
| `response_in_progress` | Response Agent is executing an authorized action |
| `paused_hitl` | Workflow paused; escalation delivered to human operator |
| `completed` | Workflow finished with a recorded outcome (responded, dismissed, escalated to external) |
| `failed` | Workflow terminated due to an unrecoverable error; requires manual review |

State transitions are append-only in the workflow state store. Every transition is written as a new event (the current state is derived from the sequence of events), ensuring that the full history is available for replay and post-incident review.

### 8.2 State Transition Rules

| From | To | Condition |
|---|---|---|
| `received` | `triage_in_progress` | Orchestration Agent accepts the alert |
| `triage_in_progress` | `investigation_in_progress` | Triage complete; Orchestration Agent delegates investigation |
| `triage_in_progress` | `response_in_progress` | Triage complete; authorization gate passed |
| `triage_in_progress` | `paused_hitl` | HITL trigger condition met |
| `investigation_in_progress` | `response_in_progress` | Investigation complete; authorization gate passed |
| `investigation_in_progress` | `paused_hitl` | HITL trigger condition met |
| `response_in_progress` | `completed` | Response action confirmed |
| `response_in_progress` | `paused_hitl` | Response failed; requires human review |
| `paused_hitl` | `triage_in_progress` | Human decision: re-triage |
| `paused_hitl` | `investigation_in_progress` | Human decision: investigate |
| `paused_hitl` | `response_in_progress` | Human decision: respond (new authorization token issued) |
| `paused_hitl` | `completed` | Human decision: dismiss or escalate externally |
| Any | `failed` | Unrecoverable error logged; no recovery path available |

---

## 9. Deployment Architecture

### 9.1 Reference Deployment (MVP)

The MVP reference deployment runs on Docker Compose. It is the minimum viable topology that makes the architectural boundaries between components tangible.

```
┌──────────────────────────────────────────────────────────────────┐
│  Docker Compose network                                          │
│                                                                  │
│  ┌─────────────────────┐   ┌──────────────────────────────────┐ │
│  │  sentinel-core      │   │  sentinel-persistence            │ │
│  │  (agent runtime +   │   │  (PostgreSQL — workflow state,   │ │
│  │   policy engine +   │   │   investigation artifacts,       │ │
│  │   audit log writer +│   │   audit log)                     │ │
│  │   HITL interface)   │   └──────────────────────────────────┘ │
│  └──────────┬──────────┘                                        │
│             │                                                    │
│  ┌──────────▼──────────┐   ┌──────────────────────────────────┐ │
│  │  sentinel-ingest    │   │  sentinel-cli                    │ │
│  │  (event bus,        │   │  (policy validation, log         │ │
│  │   deduplication,    │   │   inspection, replay)            │ │
│  │   routing)          │   └──────────────────────────────────┘ │
│  └─────────────────────┘                                        │
└──────────────────────────────────────────────────────────────────┘
         │ inbound webhooks
         ▼
   [ External alert sources ]
```

Service-to-service communication within the Docker network uses mTLS. Services do not communicate over cleartext HTTP inside the deployment boundary.

### 9.2 Production Topology Considerations

Production deployments are out of scope for the MVP but are a planning constraint for architectural decisions. The architecture MUST NOT have properties that prevent the following production topology from being possible in a later release:

- **Horizontal scaling of the ingestion layer** — multiple ingest processes behind a load balancer, sharing the event bus
- **High-availability persistence** — the workflow state store and audit log on replicated storage
- **Isolated agent execution** — each agent role running in a separate process with no shared memory
- **External secrets management** — all Tier 1 (RESTRICTED) credentials retrieved from an external secrets manager (Vault, AWS Secrets Manager) rather than environment variables

### 9.3 Reference Hardware

The MVP reference deployment is documented and tested on:
- 4 vCPU, 8 GB RAM
- 50 GB persistent storage (minimum)

Performance characteristics at other hardware configurations are not yet characterized. Performance optimization is deferred to post-MVP.

---

## 10. Cross-Cutting Concerns

### 10.1 Observability

Sentinel AI MUST emit structured telemetry from all components. At MVP, the minimum observability surface is:

| Signal type | Minimum coverage |
|---|---|
| Structured logs | All component startup/shutdown, all errors, all policy decisions |
| Metrics | Alert ingestion rate, triage latency (p50/p95/p99), policy evaluation latency, audit log write latency, HITL escalation count and delivery status |
| Traces | End-to-end trace per alert workflow (ingestion → triage → investigation/response → completion) |

OpenTelemetry is the target telemetry standard (implemented post-MVP per `docs/VISION.md` §4 v0.4). At MVP, structured JSON logs to stdout are the minimum; they MUST be machine-parseable and MUST include the session ID and workflow ID in every log line that relates to an in-flight workflow.

### 10.2 Error Handling

Error handling follows charter EP8 (failure modes are defined before deployment). The platform-wide error handling contract:

- **Fail closed, not open.** An error in the policy engine MUST produce `deny`. An error in the audit log write path MUST halt the action. An error in HITL delivery MUST produce a platform alert, not a silent skip.
- **No silent failures.** Every error is logged with the component identifier, the operation that failed, the error class, and the workflow/session ID if applicable.
- **Partial results are preferable to no results.** An agent that encounters a tool failure should produce a partial result with documented gaps rather than failing entirely, where the partial result is useful. This applies to the Investigation Agent (`agents/AGENTS.md` §4.3); it does not apply to the Response Agent or the policy engine, where partial execution is worse than no execution.

### 10.3 Configuration

Platform configuration is categorized by classification:

| Category | Storage | Example |
|---|---|---|
| Tier 1 (RESTRICTED) secrets | External secrets manager (production); environment variables (development only) | Model API keys, integration credentials |
| Policy files | Version-controlled repository | Agent capability grants, HITL thresholds |
| Deployment configuration | Version-controlled repository (non-secret values only) | Routing rules, retention periods, notification channels |
| Runtime tuning | Deployment configuration | Timeouts, concurrency limits, deduplication window |

Configuration that affects agent behavior or policy evaluation MUST be version-controlled. Configuration drift between the deployed state and the version-controlled state is a process violation.

### 10.4 Versioning

The platform follows Semantic Versioning (`docs/ENGINEERING.md` §11). Architecture-level versioning rules:

- A change to the OCSF schema version targeted by the platform is a minor version bump
- A change to the workflow state event schema is a minor version bump with a documented migration path
- A change to the audit log entry format is a minor version bump with a backward-compatible reader
- A change to the policy engine evaluation API (the interface agents call to request actions) is a major version bump from v1.0 onward

---

## 11. Architectural Decision Index

All architectural decisions with meaningful alternatives are recorded as ADRs in `.ai/decisions/`. This index maps decisions to documents.

| ADR | Decision | Status |
|---|---|---|
| [ADR-001](.ai/decisions/ADR-001-ocsf-event-schema.md) | Adopt OCSF as the canonical internal event schema | Accepted |

**Pending ADRs** (decisions that require recording before the affected component is implemented):

| Decision area | Blocking scope |
|---|---|
| License selection | Contributing guidelines, SBOM, release artifact terms |
| Model provider abstraction interface | Model interface implementation; model substitutability (charter AP6) |
| Persistence backend selection | Workflow state store and audit log implementation |
| RBAC enforcement mechanism | Authentication/authorization layer implementation |

---

*Amendments to this document that change component boundaries (§4), trust boundary assignments (§6), state model transitions (§8.2), or the ADR index (§11) require an ADR and maintainer council review. These are load-bearing decisions that affect every contributor working on the platform.*
