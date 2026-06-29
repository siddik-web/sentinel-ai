# Project Charter — Sentinel AI

> **Status:** Living document — reviewed quarterly, amended via `.ai/decisions/`  
> **Audience:** Contributors, maintainers, security researchers, adopting organizations  
> **Last updated:** 2026-Q2

---

## Table of Contents

1. [Vision](#1-vision)
2. [Mission](#2-mission)
3. [Problem Statement](#3-problem-statement)
4. [Why Sentinel AI Exists](#4-why-sentinel-ai-exists)
5. [Goals](#5-goals)
6. [Non-Goals](#6-non-goals)
7. [Target Users](#7-target-users)
8. [Core Principles](#8-core-principles)
9. [Product Pillars](#9-product-pillars)
10. [Success Metrics](#10-success-metrics)
11. [MVP Scope](#11-mvp-scope)
12. [Long-Term Roadmap](#12-long-term-roadmap)
13. [Engineering Philosophy](#13-engineering-philosophy)
14. [AI Principles](#14-ai-principles)
15. [Open Source Principles](#15-open-source-principles)

---

## 1. Vision

A world where AI agents can be deployed, monitored, and governed with the same rigour and auditability that mature engineering organizations apply to production software — without requiring those organizations to build that infrastructure from scratch.

---

## 2. Mission

Sentinel AI provides the runtime, observability, and governance layer for multi-agent AI systems. It makes it possible to run autonomous AI workflows in production with confidence: knowing what agents decided, why they decided it, what they changed, and whether they stayed within policy.

---

## 3. Problem Statement

AI agents are being deployed into production pipelines faster than the tooling to govern them has matured. Organizations running agent-based systems today face three compounding problems:

**Opacity.** LLM-based agents produce outputs that are difficult to audit. When something goes wrong — a wrong answer, an unintended action, a policy violation — there is often no durable, structured record of the reasoning chain, the tools called, or the state transitions that led to the outcome.

**Ungoverned autonomy.** Agents can call external APIs, write to databases, trigger downstream workflows, and send communications. Most frameworks offer no principled way to declare what an agent is allowed to do, enforce those boundaries at runtime, and alert when they are approached or violated.

**Operational fragility.** Multi-agent systems built on today's frameworks lack the reliability primitives that backend engineers expect: structured retries, circuit breakers, dead-letter handling, deterministic replay, and testable agent behaviour. The result is systems that work in demos but fail under production load or adversarial input.

These problems compound when organizations scale beyond a single agent or a single team. What starts as a pragmatic prototype becomes an unauditable, ungovernable system that security and compliance teams cannot sign off on.

---

## 4. Why Sentinel AI Exists

Existing solutions address parts of this problem:

- **LLM frameworks** (LangChain, LlamaIndex, CrewAI) focus on agent construction, not governance or runtime safety.
- **Observability platforms** (Langfuse, LangSmith, Phoenix) provide traces and evals but are passive — they record what happened, they do not enforce what is allowed.
- **Policy engines** (OPA, Cedar) are general-purpose and require significant integration work to apply to LLM-native agent patterns.

None of them treat the agent as a first-class operational entity with declared capabilities, enforced policies, auditable state, and defined failure modes.

Sentinel AI exists to fill that gap: an open, composable runtime layer that sits between your agent code and the world, providing governance, observability, and control without requiring you to abandon your existing tools or frameworks.

---

## 5. Goals

### G1 — Full observability of agent behaviour
Every tool call, state transition, sub-agent delegation, and external side effect is captured in a structured, queryable audit log. Operators can reconstruct exactly what an agent did and why.

### G2 — Declarative, enforceable agent policies
Agent capabilities (permitted tools, data scopes, output constraints, rate limits) are declared in code-reviewable policy files and enforced at runtime — not just documented in a README.

### G3 — Deterministic replay and testability
Any past execution can be replayed with the same inputs against an updated agent version. This enables regression testing of agent behaviour without a live LLM connection.

### G4 — Human-in-the-loop at defined checkpoints
The system provides a principled mechanism for agents to pause, surface a decision to a human operator, and resume — without losing state or requiring a full restart.

### G5 — Production reliability primitives
Structured retries with backoff, circuit breakers, bulkheads, dead-letter queues for failed agent runs, and health endpoints — applied to agent orchestration the way they are applied to microservices.

### G6 — Multi-framework compatibility
Sentinel AI wraps, not replaces, existing agent frameworks. An agent built with LangChain, Pydantic AI, or a raw Anthropic SDK call should be governable without rewriting application logic.

---

## 6. Non-Goals

These are deliberate exclusions, not oversights. Reconsidering them requires an `.ai/decisions/` entry.

| Not in scope | Reason |
|---|---|
| Building or fine-tuning LLMs | Sentinel AI governs model usage, it does not produce models. |
| End-user chat interfaces | This is a platform and runtime, not a product UI. Adopters build on top. |
| Replacing existing observability stacks | Sentinel integrates with Datadog, Grafana, OpenTelemetry — it does not replace them. |
| Agent framework development | We provide governance hooks, not a new way to write agents. |
| Multi-cloud infrastructure provisioning | Deployment is the adopter's responsibility; we provide Helm charts and Terraform modules as reference, not as a managed service. |
| General-purpose workflow orchestration | There are better tools for orchestrating non-AI workloads. Sentinel AI focuses on the specifics of LLM-native agent behaviour. |

---

## 7. Target Users

### Primary: Platform Engineers
Engineers responsible for deploying and operating AI systems within an organization. They need runtime control, operational visibility, and the ability to enforce policy without gating every agent change through a security review.

### Secondary: AI/ML Engineers
Engineers building agent-based features. They need a governance layer that does not slow down iteration — policy as code they can test locally, clear failure messages when a policy is violated, and replay tooling for debugging.

### Secondary: Security and Compliance Teams
Teams responsible for signing off on AI systems in regulated environments. They need audit logs that are complete and tamper-evident, policy declarations that are reviewable without reading agent code, and incident response tooling.

### Tertiary: Open Source Contributors and Security Researchers
Individuals contributing to the project or auditing it for vulnerabilities. They need clear contribution pathways, a security disclosure process, and architecture that is understandable without tribal knowledge.

---

## 8. Core Principles

These principles are load-bearing. When a design decision creates tension between them, the higher-numbered principle yields to the lower-numbered one.

**P1 — Correctness before convenience.**  
A governance platform that can be bypassed or that produces incorrect audit records is worse than no governance platform. We prioritize getting the semantics right over making the API ergonomic.

**P2 — Explicit over implicit.**  
Agent capabilities, policies, and failure modes are declared in structured, version-controlled files. Behaviour that emerges from undocumented defaults is a defect, not a feature.

**P3 — Fail safely.**  
When Sentinel AI cannot determine whether an action is permitted — due to a policy parse error, a network timeout, or an ambiguous policy match — the default is to deny and surface the ambiguity to an operator. Never fail open.

**P4 — Auditable by design.**  
Every runtime decision that could affect a security or compliance posture must be loggable with enough context to reconstruct it later. Audit log completeness is a functional requirement, not an afterthought.

**P5 — Composable, not monolithic.**  
Adopters should be able to use the audit log without the policy engine, or the policy engine without the replay system. Components have stable interfaces and can be replaced. Lock-in is a defect.

---

## 9. Product Pillars

### Pillar 1: Governance Runtime
The core: an execution environment that wraps agent invocations, intercepts tool calls, evaluates them against declared policies, and emits structured events. This is the component every other pillar depends on.

### Pillar 2: Audit and Observability
A structured, append-only event log of agent executions. Events are OpenTelemetry-compatible and can be forwarded to existing observability infrastructure. The Sentinel query layer provides structured search and timeline reconstruction over these events.

### Pillar 3: Policy Engine
A declarative policy language (and evaluator) for expressing what agents are and are not permitted to do. Policies are stored in version-controlled files, evaluated in-process, and testable without a running agent. Heavily informed by OPA semantics.

### Pillar 4: Human-in-the-Loop (HITL) System
A durable pause-and-resume mechanism for agent executions that require human review. Includes a notification interface, a state serialisation format that survives process restarts, and a resumption API.

### Pillar 5: Replay and Testing
A deterministic replay engine that can re-execute a past agent run against a new agent version using recorded inputs and tool responses. Enables regression testing without live LLM calls.

---

## 10. Success Metrics

Success metrics are reviewed quarterly. Targets are set for the next two quarters at each review.

### Adoption
- Organizations running Sentinel AI in production (target: 10 by end of Year 1)
- Weekly active maintainers outside the founding team (target: 5 by end of Year 1)
- GitHub stars as a proxy for awareness (not a primary metric)

### Reliability
- Governance runtime overhead < 50 ms p99 per agent invocation
- Audit log completeness: 0 missing events for governed executions in CI
- Zero silent policy bypasses in production-validated test suite

### Governance effectiveness
- Policy violation detection rate in test corpus (target: 100% for defined violation types)
- Mean time from policy violation to operator alert < 30 seconds
- Audit log reconstruction accuracy: 100% for recorded executions

### Ecosystem health
- Time to first contribution for new contributors (target: < 2 hours with documented setup)
- Security disclosures acknowledged within 48 hours
- Open issues older than 90 days without triage: 0

---

## 11. MVP Scope

The MVP proves the core value proposition: that an agent's tool calls can be governed and audited without modifying the agent's application logic.

### In scope for MVP

- **Governance runtime wrapper** for Python agents using the Anthropic SDK and LangChain
- **Structured audit log** (JSON Lines, local filesystem and S3-compatible targets)
- **Basic policy engine** supporting: tool allowlist/denylist, rate limits per tool, output size constraints
- **CLI** for policy validation, log inspection, and single-run replay
- **Docker-based local development environment**
- **Documentation**: quickstart, policy reference, architecture overview

### Out of scope for MVP

- Web UI or dashboard
- Multi-agent orchestration governance (single-agent only)
- HITL system (deferred to v0.3)
- Integrations with external observability platforms
- High-availability deployment configurations

### MVP exit criteria

1. A governance-wrapped LangChain agent can be run locally with a policy file that denies a specific tool call.
2. The denied call is recorded in the audit log with the policy rule that triggered the denial.
3. A replay of the run against a modified agent produces a deterministic result.
4. Setup to working example takes < 15 minutes following the quickstart.
5. The policy engine has a test suite with > 90% branch coverage.

---

## 12. Long-Term Roadmap

Roadmap items are indicative. Sequencing depends on contributor availability, adopter feedback, and technical dependencies. Each item will be scoped in a dedicated issue before work begins.

### v0.1 — MVP (Foundation)
Core governance runtime, audit log, basic policy engine, CLI, single-agent Python support.

### v0.2 — Multi-Agent
Governance of delegating agents (sub-agent calls). Policy propagation across agent hierarchies. Parent/child execution tracing.

### v0.3 — Human-in-the-Loop
Durable pause/resume. Notification adapters (webhook, email, Slack). Operator review UI (minimal).

### v0.4 — Observability Integrations
OpenTelemetry exporter. Grafana dashboard templates. Datadog and Honeycomb forwarders.

### v0.5 — Replay and Testing
Deterministic replay engine. Agent regression test harness. CI integration for automated policy compliance checks.

### v1.0 — Production-ready
HA deployment configurations. SLA-grade audit log durability guarantees. SOC 2 Type II alignment documentation. Security audit by independent third party.

### Post-1.0 (directional)
- Language support beyond Python (TypeScript/Node.js)
- Framework adapters: Pydantic AI, AutoGen, Crew AI
- Policy marketplace: community-contributed policies for common compliance frameworks (GDPR, HIPAA, SOC 2)
- Federated governance: policy management across multiple organizations sharing an agent ecosystem

---

## 13. Engineering Philosophy

### Understand the problem before writing the solution
Design decisions are recorded in `.ai/decisions/` with the problem statement, alternatives considered, and the rationale for the choice made. Code that implements an undocumented decision is incomplete.

### Make behaviour observable and testable at every layer
Components are designed to be independently testable. The governance runtime can be unit-tested without a running LLM. The policy engine can be tested without an agent. Replay works without external network calls.

### Prefer boring technology for infrastructure concerns
The audit log is append-only JSON Lines, not a bespoke binary format. The policy language is a subset of a well-understood paradigm, not a novel DSL. Novel technology is reserved for the problems that genuinely require it.

### Correctness is non-negotiable, performance is optimizable
A governance runtime that silently drops audit events or misapplies a policy is broken, regardless of its throughput. We fix correctness issues before performance issues. We measure before optimizing.

### Security is a design constraint, not a review gate
Threat modeling happens at the design stage, not after implementation. Security-relevant changes require a documented threat analysis. There is no "we'll harden it later."

### Small, reviewable changes ship faster than large ones
PRs are scoped to a single coherent change. A PR that refactors and adds a feature is two PRs. The overhead of splitting is real; the overhead of reviewing a 2,000-line PR is higher.

---

## 14. AI Principles

These principles govern how Sentinel AI uses AI internally (in its own tooling, agent test harnesses, and documentation generation) and how it expects adopters to use AI through its governance layer.

### Transparency of capability
An agent's declared capabilities must match its actual capabilities. A policy that permits tool `X` is a statement that the agent is expected to call tool `X`. Capability creep — agents doing things not declared in policy — is a governance failure.

### Human accountability is non-negotiable
Autonomous agent decisions do not eliminate human accountability. Every agent operating under Sentinel AI's governance layer must have a named human or team accountable for its behaviour. The audit log supports this accountability; it does not replace it.

### Minimal capability by default
Agents should be granted the minimum tool access, data scope, and output permissions required for their declared purpose. Policies should start restrictive and expand with evidence, not the reverse.

### Alignment between stated and actual behaviour
Evaluation is a first-class concern. Agents whose outputs drift from their declared purpose — even if no policy is technically violated — represent a governance risk. The replay and testing pillar exists to surface this drift before it reaches production.

### No dark patterns
Sentinel AI will not implement features that obscure agent behaviour from the humans accountable for it, make it harder to audit an agent's actions, or help an agent circumvent its own declared policy.

---

## 15. Open Source Principles

### Why open source
Governance infrastructure for AI systems must be auditable by the people who depend on it. A closed governance platform cannot be trusted in the same way an open one can — users must be able to read the policy evaluation logic, the audit log format, and the replay engine to verify they work as documented.

### License
Sentinel AI is licensed under the **Apache License 2.0**. This allows commercial use and modification while requiring attribution and preserving patent rights. It was chosen over MIT for its explicit patent grant and over AGPL to avoid constraining adopters who run Sentinel as a service.

### Governance model
The project uses a **Benevolent Dictator with Council** model during the pre-1.0 phase. Maintainers from contributing organizations form the council. Significant decisions (API changes, roadmap priorities, license changes) require council consensus. Operational decisions (PR review, issue triage, release cuts) are delegated to individual maintainers.

### Contribution expectations
- Contributions are welcome from individuals and organizations.
- All contributors must sign the project CLA (Contributor License Agreement) before a PR can be merged.
- Contributions that expand Sentinel AI's capabilities must include documentation, tests, and where applicable a threat analysis.
- Security vulnerability disclosures follow the process documented in `SECURITY.md`. Public disclosure is not made before a patch is available and adopters have had reasonable time to upgrade.

### Sustainability
Open source projects that do not address sustainability fail. Sentinel AI's sustainability plan includes:
- A documented path for organizations that depend on Sentinel AI to fund its development.
- Recognition of significant contributors in release notes and project governance.
- No features that exist solely to drive commercial upsell — all governance primitives remain in the open-source core.

---

## Amendment Process

This charter is a living document. Changes are proposed via GitHub issue, discussed openly, and recorded as a decision in `.ai/decisions/` before the charter is updated. Changes to Core Principles (§8) or AI Principles (§14) require a two-week comment period and council consensus.

---

*Sentinel AI is an open source project. Nothing in this charter creates a warranty, support obligation, or contractual commitment.*
