# PROJECT_CHARTER — Sentinel AI

> **Document class:** Foundational governance  
> **Status:** Active — ratified at project inception  
> **Revision cadence:** Quarterly review; amendments require an entry in `.ai/decisions/`  
> **Audience:** Software Architects, Security Engineers, AI Engineers, Open Source Contributors, Adopting Organizations

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Vision](#2-vision)
3. [Mission](#3-mission)
4. [Problem Statement](#4-problem-statement)
5. [Why Sentinel AI Exists](#5-why-sentinel-ai-exists)
6. [Goals](#6-goals)
7. [Non-Goals](#7-non-goals)
8. [Target Users](#8-target-users)
9. [Product Principles](#9-product-principles)
10. [Engineering Principles](#10-engineering-principles)
11. [AI Principles](#11-ai-principles)
12. [Success Metrics](#12-success-metrics)
13. [MVP Scope](#13-mvp-scope)
14. [Long-Term Vision](#14-long-term-vision)
15. [Glossary](#15-glossary)

---

## 1. Executive Summary

Security operations teams are overwhelmed. The volume of alerts, the complexity of modern attack surfaces, and the shortage of skilled analysts mean that most organizations are permanently behind. Existing SIEM and SOAR platforms address the data aggregation problem but not the reasoning problem: they collect and correlate events, but they require human analysts to interpret them, decide what matters, and execute the right response at the right time.

Sentinel AI is an open-source AI Security Response Platform that introduces a reasoning layer into the security operations workflow. It deploys specialized AI agents that detect anomalies, triage alerts, investigate incidents, and recommend or execute responses — operating continuously, at machine speed, within boundaries defined by the operators who deploy them.

The platform is designed for organizations that need the analytical depth of a senior security engineer available at the scale and speed of software. It is built to be auditable, governable, and extensible — because a security platform that cannot itself be secured and understood is not a security platform.

This charter is the foundation document. Every architectural decision, product tradeoff, and engineering standard in Sentinel AI traces back to what is written here. Changes to this document change the project.

---

## 2. Vision

Security operations that are continuous, consistent, and comprehensible — where AI augments human judgment rather than obscuring it, and where every decision made by an automated system is explainable, auditable, and correctable.

The endgame is not autonomous security. It is *assisted* security: AI agents that eliminate the toil of alert triage, accelerate incident investigation, and surface the right information to the right person at the right time, while keeping humans accountable for consequential decisions.

---

## 3. Mission

Sentinel AI's mission is to make enterprise-grade AI-driven security response accessible to any organization — not just those with the budget to build and operate it from scratch.

Concretely:

- Provide a runtime for deploying AI agents that reason over security events and take defined actions in response.
- Ensure every agent decision is observable, explainable, and governed by operator-defined policy.
- Build in the open so that the platform itself can be audited, hardened, and trusted.
- Reduce the time between an attacker's first move and a defender's informed response.

---

## 4. Problem Statement

### 4.1 The Alert Tsunami

Enterprise security tooling generates more alerts than human teams can process. Industry data consistently shows that security operations centers (SOCs) handle hundreds to thousands of alerts per analyst per day, with false positive rates frequently exceeding 50%. The result: real threats are buried in noise, analyst burnout is endemic, and mean time to detect (MTTD) remains stubbornly high.

### 4.2 The Reasoning Gap

Current automation — SOAR playbooks, correlation rules, threshold-based alerting — is deterministic. It executes a fixed procedure when a fixed condition is met. This works for known, well-defined attack patterns. It fails for novel threats, multi-stage attacks that cross tool boundaries, and attacker behavior that deliberately stays below static thresholds.

The reasoning required to connect a failed authentication spike in IAM, an unusual outbound connection from a workload, and an anomalous API call pattern is not reducible to a rule. It requires contextual judgment. That judgment currently lives exclusively in human analysts.

### 4.3 The Expertise Bottleneck

The global shortage of experienced security engineers is structural. Organizations cannot hire their way to adequate security coverage. Junior analysts can triage high-confidence, high-signal alerts; they cannot reliably investigate complex, multi-vector incidents. The expertise to do so is scarce, expensive, and unavailable at 3 AM when an attacker is moving laterally.

### 4.4 The Auditability Deficit

When AI is introduced into security workflows today — whether as an ML model scoring alerts or a generative AI assistant advising analysts — it typically operates as a black box. The score exists; the reasoning does not. This creates a compliance problem (how do you audit a decision you cannot explain?), a trust problem (how do you calibrate reliance on a system you cannot inspect?), and an improvement problem (how do you make the system better if you cannot see where it went wrong?).

### 4.5 The Integration Tax

Security teams operate heterogeneous environments. Data lives in SIEMs, cloud provider logs, endpoint detection platforms, identity providers, network monitoring tools, and ticketing systems. Building agentic security tooling that works across this landscape requires substantial integration engineering — work that every organization currently does independently, at great cost, producing results that are not reusable.

---

## 5. Why Sentinel AI Exists

The market already contains SIEM platforms (Splunk, Microsoft Sentinel, Elastic), SOAR platforms (Palo Alto XSOAR, Splunk SOAR, Tines), and AI-assisted security tools (Darktrace, Vectra, CrowdStrike Charlotte AI). Sentinel AI is not a direct replacement for any of them. It exists because none of them solve the full problem:

| Category | What they solve | What they leave unsolved |
|---|---|---|
| **SIEM** | Data aggregation and search | Reasoning over aggregated data at scale |
| **SOAR** | Automating known response playbooks | Handling novel threats that don't match existing playbooks |
| **AI-assisted tooling** | Augmenting analyst speed within a single vendor's platform | Cross-stack reasoning; open auditability; operator-defined governance |
| **LLM security assistants** | Natural language interface to security data | Autonomous action; structured audit trails; policy enforcement |

Sentinel AI fills the gap between these categories: an open, composable runtime for AI agents that can reason across stack boundaries, take defined actions, and do so within a governance framework that security and compliance teams can inspect and verify.

The open-source model is not incidental. Security infrastructure that organizations cannot audit is security infrastructure they cannot fully trust. Openness is a functional requirement, not a distribution strategy.

---

## 6. Goals

### G1 — Continuous, autonomous alert triage
AI agents evaluate incoming security alerts against context (asset criticality, threat intelligence, historical patterns, environmental state) and produce a structured triage output: severity, confidence, reasoning, recommended action. The goal is to reduce the volume of alerts requiring human review by handling high-confidence, low-ambiguity cases automatically.

### G2 — Multi-source incident investigation
Agents can correlate events across heterogeneous data sources — logs, alerts, network telemetry, identity events, cloud API activity — to construct a coherent incident timeline without manual pivot work. The investigation trace is persisted as a structured artifact, not a chat transcript.

### G3 — Governed autonomous response
For a defined set of response actions (isolating a workload, revoking a credential, blocking an IP, creating a ticket), agents can execute responses autonomously when confidence and severity thresholds are met. Every autonomous action is logged with the evidence and policy evaluation that authorized it.

### G4 — Human-in-the-loop escalation
When confidence is below threshold, when severity is above a configurable ceiling, or when a policy rule explicitly requires human review, the agent pauses and escalates — with a structured summary of findings and a clear articulation of what decision is needed. The platform does not make humans optional; it makes their time count.

### G5 — Full auditability of agent decisions
Every agent decision — what data was retrieved, what reasoning was applied, what policy was evaluated, what action was taken or recommended — is captured in a structured, tamper-evident audit log. This log must be sufficient to reconstruct the full decision chain in a post-incident review or compliance audit.

### G6 — Operator-defined, code-reviewable policy
What agents are permitted to do — which data sources they can query, which actions they can execute, which escalation paths they must follow — is declared in versioned policy files that operators can read, review in a pull request, and test before deployment. Policy is not configuration buried in a UI; it is code.

### G7 — Composable integration with existing security stacks
Sentinel AI does not require organizations to replace their existing tooling. It provides adapters for common data sources and response targets, and a documented integration interface for building new adapters. The platform amplifies existing investment; it does not replace it.

---

## 7. Non-Goals

Sentinel AI deliberately does not attempt to solve the following problems. Each exclusion is a reasoned decision, not an oversight. Revisiting any of them requires a recorded decision in `.ai/decisions/`.

| Not in scope | Reason |
|---|---|
| **Replacing a SIEM** | Sentinel AI consumes events from SIEMs; it does not replace the data layer. |
| **Vulnerability management** | Identifying and tracking vulnerabilities in software is a distinct discipline with mature tooling. Sentinel AI operates on runtime events, not static analysis. |
| **Penetration testing or red teaming** | The platform is defensive. Offensive tooling is out of scope and would create unacceptable dual-use risk. |
| **Compliance reporting and GRC** | Sentinel AI produces evidence that compliance tools can consume; it is not a GRC platform. |
| **Endpoint detection and response (EDR)** | EDR requires deep OS-level integration. Sentinel AI operates at the event and API layer above it. |
| **Building or training security-specific models** | The platform uses existing models through defined interfaces. Model development is a separate research problem. |
| **Managing security tooling configuration** | Sentinel AI responds to security events; it does not manage the configuration of the tools that generate them. |
| **Consumer or SMB security products** | The operational model (policy as code, integration engineering, agent governance) is designed for organizations with dedicated security and engineering functions. |

---

## 8. Target Users

### 8.1 Security Operations Engineers

Engineers responsible for the day-to-day operation of a SOC or security team's tooling. They deploy and maintain Sentinel AI, author and review agent policies, build and maintain data source integrations, and own the reliability of the platform.

**What they need:** Clear operational documentation, reliable deployment tooling, observable runtime behavior, testable policies, and the ability to constrain agent behavior precisely.

### 8.2 Security Analysts

Analysts who work with security events daily — triaging alerts, investigating incidents, executing response actions. Sentinel AI changes their workflow by handling high-confidence triage autonomously and presenting investigated incident summaries rather than raw alert feeds.

**What they need:** Trustworthy triage outputs with legible reasoning, clear escalation paths that surface the right context, and confidence that autonomous actions taken on their behalf are correct and auditable.

### 8.3 Security Architects

Architects designing the security posture of an organization, evaluating tools, and making build-vs-buy decisions. They assess Sentinel AI for architectural fit, threat model implications, data handling, and integration complexity.

**What they need:** Clear architecture documentation, an honest threat model for the platform itself, a well-defined data flow and trust boundary model, and documented integration interfaces.

### 8.4 AI/ML Engineers

Engineers building, extending, or adapting AI agents within Sentinel AI. They implement new detection logic, build domain-specific reasoning chains, and integrate new model capabilities.

**What they need:** A well-defined agent interface, a testing harness that does not require live data, clear documentation of the reasoning and tool-use contracts, and a governance framework they can work within rather than around.

### 8.5 Open Source Contributors

Individuals contributing to the project — implementing features, fixing bugs, writing integrations, improving documentation, or auditing the codebase for security vulnerabilities.

**What they need:** A clear contribution pathway, reproducible development environment, documented architecture, well-scoped issues, and a security disclosure process that protects responsible disclosure.

### 8.6 Compliance and Security Assurance Teams

Teams responsible for ensuring that security tooling meets regulatory and organizational requirements. They audit Sentinel AI deployments for data handling, access control, audit log completeness, and policy compliance.

**What they need:** A complete data flow inventory, a documented control set, tamper-evident audit logs, and architecture that separates concerns clearly enough to scope a compliance review.

---

## 9. Product Principles

These principles govern product decisions — what to build, how to prioritize, and what tradeoffs to make. They are not aspirational; they are decision filters. When two options are in tension, these principles determine which wins.

### PP1 — Explainability is not optional
Every agent output that influences a security decision must include the reasoning that produced it, the evidence it relied on, and the confidence with which it was reached. An unexplained score or recommendation is not an acceptable output from a security system.

*Why:* Security decisions have consequences. Analysts need to calibrate their reliance on agent outputs. Compliance auditors need to reconstruct decisions. Post-incident reviews need to understand what the platform did and why. Opacity defeats all of these.

### PP2 — Govern before you automate
An agent should not be authorized to take an action autonomously until the policy governing that action has been written, reviewed, and tested. Automation without governance is operational risk, not operational efficiency.

*Why:* Autonomous action in a security context can cause harm — an incorrectly isolated workload, a revoked credential for the wrong account, a blocked IP that is actually a legitimate service. The cost of getting governance right before enabling automation is far lower than the cost of remediation.

### PP3 — Human escalation is a first-class feature
The path from an agent to a human analyst must be as carefully designed as the path from an event to an agent. Escalation should surface a structured, actionable summary — not a raw alert dump. Humans should always have the option to override agent decisions.

*Why:* The goal is human-AI collaboration, not human replacement. A platform that makes escalation an afterthought — or that escalates in a way that is harder to act on than the original alert — defeats its own purpose.

### PP4 — The platform must be auditable, including by adversaries
The audit log, the policy engine, and the reasoning traces are not just for operators. Security researchers, penetration testers, and potentially adversaries will attempt to understand how the platform makes decisions. Designing for auditability means designing for scrutiny. Obscurity is not a control.

*Why:* Security through obscurity fails. An open platform that is designed with adversarial scrutiny in mind is more trustworthy than a closed one that relies on obscurity. This also aligns with the open-source commitment.

### PP5 — Integrations are a core product surface, not an afterthought
The value of Sentinel AI is proportional to the breadth and reliability of its integrations with existing security tooling. A beautiful reasoning engine that cannot connect to the data sources an organization actually uses is not useful. Integration quality is product quality.

*Why:* Organizations will not replace their data infrastructure to adopt Sentinel AI. The integration layer must be first-class: well-documented, tested with real data shapes, and versioned alongside the core platform.

---

## 10. Engineering Principles

These principles govern how the platform is built and maintained. They exist because good security software requires more than good intentions — it requires habits that produce consistently correct, maintainable, and auditable code.

### EP1 — Correctness before performance
A security platform that produces incorrect results faster is worse than one that produces correct results more slowly. Performance is a quality attribute; correctness is a functional requirement. We measure before optimizing, and we fix correctness defects before performance defects.

### EP2 — Security is a design constraint, not a review gate
Threat modeling is done at design time. Security-relevant changes — changes to the audit log, the policy engine, the authentication layer, or any external integration — require a documented threat analysis before implementation begins. "We'll harden it later" is not an acceptable engineering posture for a security platform.

### EP3 — Explicit state, explicit transitions
Agent state and state transitions are modeled explicitly. Implicit state — state embedded in variables, inferred from control flow, or stored outside of the defined state model — is a defect. This is especially critical for the HITL escalation and autonomous response paths, where incomplete state transitions can leave the system in an inconsistent condition.

### EP4 — Every external dependency is a trust boundary
Any component outside the Sentinel AI process — a model provider API, a data source, a response target, a notification system — is a potential source of malicious or malformed input. All external inputs are validated against a defined schema before processing. Trust is never assumed based on network location or transport security alone.

### EP5 — Testability is an architectural requirement
Components are designed to be testable in isolation. The policy engine does not require a running agent. The agent reasoning harness does not require a live model API. The audit log writer does not require a real storage backend. Dependencies are injected; interfaces are stable; test doubles are first-class.

### EP6 — Minimize attack surface
The platform exposes only what is necessary. Unused capabilities are not compiled in. Default configurations are restrictive. Permissions are granted explicitly and with minimum scope. This applies to the platform's own runtime, to the agents it deploys, and to the integrations it manages.

### EP7 — Changes are small, reviewable, and documented
Pull requests are scoped to a single coherent change. Architectural decisions that affect the platform's security posture, data model, or public interfaces are documented in `.ai/decisions/` before implementation. The commit history is a record of intent, not just of diff.

### EP8 — Failure modes are defined before deployment
Before any component is deployed to a production-equivalent environment, its failure modes are documented: what happens if it crashes, times out, receives malformed input, or encounters an unexpected state. The correct failure behavior for a security component is almost always to fail safely and alert — not to fail silently or to fail open.

---

## 11. AI Principles

These principles govern how AI is used within Sentinel AI — both in the agents the platform deploys and in any AI tooling used in the development of the platform itself.

### AP1 — AI augments human judgment; it does not replace human accountability
Every agent operating under Sentinel AI has a named human or team accountable for its behavior. Accountability does not transfer to the model, the framework, or the platform vendor. The audit log exists to support human accountability, not to satisfy it.

### AP2 — Confidence must be communicated, not assumed
Every agent output that drives a decision includes a confidence signal and the factors that produced it. An agent that is uncertain says so. Overclaiming confidence in a security context — presenting a guess as a determination — is a safety defect.

### AP3 — Minimal capability by default
Agents are granted the minimum data access, tool permissions, and response authority required for their declared function. Capability is expanded with evidence and justification, never granted speculatively. A policy that permits an action is a statement that the action has been reviewed and authorized, not a permission slip for future actions.

### AP4 — Reasoning traces are preserved
The chain of evidence, retrieval steps, and reasoning that produced an agent output is stored alongside the output. The trace must be sufficient to allow a human analyst to evaluate the quality of the reasoning independently — not just the correctness of the conclusion.

### AP5 — Adversarial inputs are expected
Agents operating in a security context will encounter inputs that are deliberately crafted to mislead them — prompt injection in log data, adversarially crafted alert payloads, inputs designed to trigger false negatives. The platform treats adversarial input as a design constraint, not an edge case.

### AP6 — Model substitutability is a design requirement
No component of Sentinel AI should depend on behavior that is specific to a single model version or provider. Model interfaces are abstracted. Evaluation suites test behavior across model variants. The platform's correctness guarantees must hold regardless of which conformant model is behind the interface.

### AP7 — Continuous evaluation is not optional
Agent behavior degrades as models update, data distributions shift, and attack patterns evolve. Evaluation is not a one-time gate at deployment; it is a continuous process. Regression in agent performance on defined behavioral benchmarks is treated as a defect.

---

## 12. Success Metrics

Metrics are reviewed quarterly. The targets below are for the end of Year 1 post-initial release. Revised targets are set at each quarterly review and recorded in `.ai/decisions/`.

### Operational Effectiveness

| Metric | Target | Notes |
|---|---|---|
| Mean time to triage (MTTT) | ≤ 2 min for automated cases | Measured from alert ingestion to structured triage output |
| False positive rate on automated triage | ≤ 5% | Measured against analyst-confirmed ground truth |
| Alert-to-investigation escalation rate | ≥ 60% reduction vs. baseline | Fraction of alerts requiring full human investigation |
| Autonomous response accuracy | ≥ 99% | Actions taken must match analyst-verified correct action |

### Platform Reliability

| Metric | Target |
|---|---|
| Audit log completeness | 100% for governed agent executions — zero silent drops |
| Policy evaluation latency | p99 ≤ 100 ms per agent action |
| Governance runtime uptime | ≥ 99.9% in reference deployment |
| HITL escalation delivery | 100% — no dropped escalations |

### Security of the Platform

| Metric | Target |
|---|---|
| Critical/high CVEs in open state | 0 — patched within 14 days of disclosure |
| Security disclosures acknowledged | 100% within 48 hours |
| Independent security audit | Completed before v1.0 release |
| Penetration test findings remediated | 100% of critical/high prior to v1.0 |

### Ecosystem and Adoption

| Metric | Target |
|---|---|
| Organizations in production | ≥ 10 by end of Year 1 |
| Active maintainers outside founding team | ≥ 5 |
| Data source integrations (production-quality) | ≥ 8 at v1.0 |
| Time-to-first-contribution for new contributors | ≤ 2 hours with documented setup |

---

## 13. MVP Scope

The MVP validates the core thesis: that an AI agent can triage a real security alert with sufficient accuracy and transparency to be trusted by a security analyst.

### In Scope

- **Alert ingestion** from a structured webhook (generic format; one reference integration with a common SIEM)
- **Single-agent triage** using a defined reasoning chain: alert context enrichment, asset lookup, threat intelligence query, severity and confidence scoring
- **Structured triage output**: severity, confidence, reasoning summary, recommended action, supporting evidence links
- **Policy engine**: tool allowlist, data scope constraints, output format validation
- **Audit log**: append-only structured log (JSON Lines) of all agent inputs, tool calls, policy evaluations, and outputs
- **HITL escalation**: configurable escalation via webhook when confidence or severity thresholds are crossed
- **CLI**: policy validation, log inspection, single-run agent replay against recorded inputs
- **Reference deployment**: Docker Compose; documented setup-to-working-example path

### Out of Scope for MVP

- Multi-agent orchestration
- Autonomous response actions (triage and recommendation only)
- Web UI or dashboard
- High-availability or distributed deployment
- Integration with more than one SIEM (additional integrations follow MVP)
- Fine-tuning or custom model training

### Exit Criteria

The MVP is complete when all of the following are verifiable:

1. An alert ingested via the webhook produces a structured triage output within 120 seconds on reference hardware.
2. A policy that prohibits a specific tool call causes the agent to halt, log the denial with the applicable policy rule, and escalate rather than proceeding.
3. A recorded agent run can be replayed deterministically against updated agent logic using the CLI.
4. The audit log for a complete alert-to-triage cycle contains every tool call, policy evaluation, and output with no gaps.
5. The setup-to-first-triage path can be completed by a new user in under 20 minutes following the quickstart documentation.
6. The triage output for a set of 20 representative alerts matches analyst-verified ground truth on severity at ≥ 85%.

---

## 14. Long-Term Vision

The milestones below represent directional intent, not a committed delivery schedule. Each milestone is scoped in dedicated issues before work begins. Sequencing reflects dependencies and expected organizational adoption patterns.

### v0.1 — Validated Triage (MVP)
Single-agent alert triage. Policy engine. Audit log. HITL escalation. CLI. Reference deployment.

### v0.2 — Response Actions
Autonomous response for a defined action set (workload isolation, credential revocation, IP block, ticket creation). Policy-gated action authorization. Response audit trail. Operator-defined approval thresholds.

### v0.3 — Multi-Source Investigation
Multi-agent coordination for incident investigation. Cross-source event correlation. Structured investigation timeline artifact. Agent-to-agent delegation with policy propagation.

### v0.4 — Observability and Operations
OpenTelemetry integration. Grafana dashboard templates. Alerting on platform health. Operator runbook for common failure modes. SLA-equivalent reliability documentation.

### v0.5 — Replay and Regression Testing
Deterministic replay engine against recorded sessions. Behavioral test harness for agents. CI integration for policy compliance and behavioral regression.

### v1.0 — Production-Grade
High-availability deployment configurations. Tamper-evident audit log with integrity verification. Independent security audit. SOC 2 Type II alignment documentation. Stable public API with deprecation policy.

### Post-v1.0 (Directional)

- **TypeScript/Node.js runtime support** — expanding beyond Python for agent authoring
- **Compliance framework mapping** — pre-built policy packs aligned to NIST CSF, CIS Controls, SOC 2, ISO 27001
- **Federated multi-organization governance** — policy management across organizational boundaries for MSSPs and enterprises with multiple security domains
- **Threat intelligence mesh** — native integration with structured threat intelligence feeds as a first-class agent data source
- **Behavioral baselining** — automated derivation of expected agent behavior from historical runs, used to detect agent drift without manual benchmark authoring

The long-term aim is not a larger platform. It is a deeply reliable, deeply auditable foundation that the security engineering community trusts enough to build on. Surface area is a liability in security software. We add capabilities when they address a real need that cannot be addressed by composition of what already exists.

---

## 15. Glossary

Terminology used consistently across all Sentinel AI documentation. Where a term has an established meaning in an external standard or framework (NIST, MITRE ATT&CK, OpenTelemetry), we align with that meaning and note the source.

| Term | Definition |
|---|---|
| **Agent** | An autonomous software component that perceives inputs, reasons over them using an LLM, calls tools to retrieve information or take actions, and produces a structured output. In Sentinel AI, agents operate within a governance envelope defined by a policy file. |
| **Alert** | A structured event produced by a security tool (EDR, SIEM, WAF, IDP, etc.) indicating that a condition of potential security significance has been detected. Alerts are the primary input to the triage agent. |
| **Audit Log** | An append-only, structured record of all agent inputs, tool calls, policy evaluations, outputs, and state transitions. The audit log is the ground truth for what the platform did and why. |
| **Autonomous Response** | An action taken by an agent against a target system (e.g., isolating a workload, revoking a credential) without requiring explicit human approval, authorized by a policy rule and a confidence/severity threshold. |
| **Capability** | A defined action that an agent is authorized to perform, such as querying a specific data source or executing a specific response action. Capabilities are declared in policy files and enforced at runtime. |
| **Confidence** | A signal produced alongside an agent output indicating the degree to which the available evidence supports the output. Confidence is used to determine whether autonomous action is authorized or HITL escalation is required. |
| **Enrichment** | The process of augmenting a raw alert with additional context — asset metadata, user identity information, threat intelligence, historical event data — to support more accurate triage. |
| **Governance Envelope** | The set of constraints — permitted tools, data scopes, output formats, rate limits, confidence thresholds, escalation rules — that define the boundaries within which an agent operates. Defined in a policy file. |
| **HITL (Human-in-the-Loop)** | A defined checkpoint in an agent workflow at which execution pauses and a structured summary is escalated to a human operator for review and decision before the agent proceeds. |
| **Incident** | A security event or cluster of events that has been assessed as representing actual or likely harm, as distinct from an alert (which may be a false positive or a low-severity condition). |
| **Integration** | A component that connects Sentinel AI to an external system — a data source (inbound) or a response target (outbound). Integrations have defined schemas and are versioned independently. |
| **Investigation** | The process of correlating events, enriching context, and constructing an incident timeline to understand the scope, origin, and impact of a security event. In Sentinel AI, investigation is performed by multi-agent coordination. |
| **MTTD (Mean Time to Detect)** | The average time between the onset of a security event and its detection. A primary effectiveness metric for security operations. |
| **MTTR (Mean Time to Respond)** | The average time between detection of a security event and completion of a response action. |
| **MTTT (Mean Time to Triage)** | Sentinel AI-specific metric: the average time between alert ingestion and production of a structured triage output. |
| **Policy** | A versioned, code-reviewable file that declares the governance envelope for one or more agents: permitted tools, data scopes, action authorizations, escalation rules, and confidence thresholds. |
| **Policy Engine** | The runtime component that evaluates agent actions against the applicable policy and produces an allow/deny/escalate decision. The policy engine is the enforcement point for all governance constraints. |
| **Reasoning Trace** | The structured record of the steps an agent took to produce an output: which data was retrieved, what intermediate conclusions were drawn, and how the final output was reached. Required for all outputs that influence security decisions. |
| **Replay** | Deterministic re-execution of a past agent run against recorded inputs and tool responses, used for debugging, regression testing, and incident reconstruction. |
| **Response Action** | A concrete operation performed against a target system as a result of an agent's analysis: isolating a workload, revoking a credential, blocking network traffic, creating a ticket, sending a notification. |
| **SIEM (Security Information and Event Management)** | A platform that aggregates, normalizes, and stores security events from across an organization's technology estate. Sentinel AI consumes events from SIEMs; it does not replace them. |
| **SOAR (Security Orchestration, Automation and Response)** | A platform that automates security workflows and playbook execution. Sentinel AI's autonomous response capability overlaps with SOAR for AI-driven cases; SOAR remains appropriate for deterministic playbooks. |
| **SOC (Security Operations Center)** | The team (and often the physical or virtual space) responsible for monitoring, detecting, and responding to security events in an organization. The primary operational context for Sentinel AI. |
| **Triage** | The process of evaluating an alert to determine its severity, likelihood of being a true positive, and appropriate next action. In Sentinel AI, triage is performed by the triage agent and produces a structured triage output. |
| **Trust Boundary** | The interface between two components where trust is not assumed and all inputs are validated. Every external dependency — model API, data source, response target — is a trust boundary. |
| **Tool** | A function exposed to an agent that performs a defined operation: querying a data source, calling an external API, writing to a log, executing a response action. Tools are the mechanism through which agents interact with the world. |

---

*This charter is maintained by the Sentinel AI core maintainer team. Questions, proposed amendments, and substantive disagreements with the content should be raised as GitHub issues referencing this document. Changes are not made directly — they are proposed, discussed, and recorded.*
