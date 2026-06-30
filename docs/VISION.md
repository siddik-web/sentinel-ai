# Vision — Sentinel AI

> **Document class:** Strategic direction
> **Status:** Active
> **Derived from:** `PROJECT_CHARTER.md` §2, §14
> **Audience:** Prospective adopters, contributors, maintainers, and security community stakeholders
> **Revision cadence:** Annually; material changes require an entry in `.ai/decisions/`

---

## Table of Contents

1. [The State We Are In](#1-the-state-we-are-in)
2. [The World We Are Building Toward](#2-the-world-we-are-building-toward)
3. [What Sentinel AI Must Become](#3-what-sentinel-ai-must-become)
4. [The Direction of Travel — v0.1 to v2.0](#4-the-direction-of-travel--v01-to-v20)
5. [What We Refuse to Build](#5-what-we-refuse-to-build)
6. [The Ecosystem Bet](#6-the-ecosystem-bet)
7. [How We Know We Are Succeeding](#7-how-we-know-we-are-succeeding)

---

## 1. The State We Are In

The security operations problem is not getting better. It is getting structurally worse.

Attack surfaces are expanding faster than the security organizations that defend them. Cloud-native architecture, distributed supply chains, API-connected services, and AI-assisted development mean that any large organization now has more exploitable surface area than any team of human analysts can monitor at human speed. The math does not close without automation.

The automation that exists today is rule-based. SOAR platforms orchestrate deterministic playbooks. SIEM correlation rules fire on known patterns. Threshold-based alerts flag known deviations. These tools are valuable and irreplaceable for what they do. What they do not do is reason. They cannot look at a failed authentication in one system, an anomalous DNS query from a workload, and an unusual API call pattern in a cloud environment — none of which individually crosses a threshold — and recognize that together they describe a specific attack progression. That inference requires judgment that is currently held, entirely, by human analysts.

The world has responded by hiring. Demand for qualified security engineers outstrips supply by a margin that has not narrowed in years. Organizations that can afford to staff adequately are the exception. Everyone else is operating on partial coverage, deferred investigations, and an alert backlog that grows faster than it can be cleared.

AI is being introduced into this environment, but mostly at the edges. Generative AI assistants answer analyst questions about threat intelligence. ML models score the alerts that SIEMs produce. Experimental large language model wrappers help analysts write queries. These are valuable marginal improvements. None of them addresses the structural problem: the reasoning gap between event and decision remains, and the responsibility for bridging it still rests entirely with a human analyst who is already overloaded.

Sentinel AI starts from the premise that this gap is closeable — but only if the AI introduced to close it operates under governance frameworks that give security organizations the confidence to actually rely on it.

---

## 2. The World We Are Building Toward

Security operations that are **continuous, consistent, and comprehensible** — where AI augments human judgment rather than obscuring it, and where every decision made by an automated system is explainable, auditable, and correctable.

This is not a vision of fully autonomous security. Autonomous action without accountability is operational risk, not operational capability. The goal is not to remove humans from security decisions — it is to ensure that human involvement is concentrated where it creates the most value: complex judgment calls, ambiguous situations, and consequential decisions, rather than the high-volume, high-certainty, low-complexity triage that consumes most of an analyst's day.

In the world we are building toward:

**Analysts are investigators, not sorters.** The first hour of an analyst's day is not clearing a queue of low-signal alerts that require the same assessment every time. It begins with a structured briefing: the high-confidence cases handled automatically overnight, the genuine anomalies that warrant attention, the in-flight investigations that need human input at a specific decision point. The analyst's judgment is applied to the cases that need it.

**AI decisions are readable, not oracular.** When an agent classifies an alert, the classification comes with the evidence it drew on, the reasoning it applied, and the confidence it holds. An analyst who disagrees with a classification can read the trace and identify where the reasoning diverged from their own judgment. They can correct it, feed that correction back into the system, and trust that the same error will not recur.

**Governance is code, not policy in a drawer.** The rules governing what agents are permitted to do — which data sources they can access, which actions they can take autonomously, which cases require human approval — are versioned, reviewable, and testable. A change to agent behavior is a pull request. It is reviewed before it reaches production. It can be rolled back.

**Security investment compounds.** The integrations an organization builds to connect Sentinel AI to their data sources are reusable and contribuable. The policy files they develop are shareable as starting points. The behavioral evaluation suites they write for their environment add to a growing commons. The platform gets more useful to every organization as the community around it grows.

---

## 3. What Sentinel AI Must Become

To realize the world described above, Sentinel AI must evolve from a capable triage tool into a trusted security operations fabric — infrastructure that security organizations build their detection and response practice on top of.

That evolution has three requirements.

### 3.1 Depth of Reasoning

A triage output is a classification. An investigation is a reconstruction. A response is an action with consequences. Each requires a different level of reasoning depth, and the platform must support all three without collapsing the distinctions between them.

The Triage Agent produces a verdict quickly with the context available in the alert and its immediate enrichment. The Investigation Agent has time, tools, and scope to construct a coherent picture of an incident from heterogeneous sources. The Response Agent acts precisely and records everything. The Orchestration Agent coordinates the workflow and holds the policy boundary between machine decision and human accountability.

As Sentinel AI matures, the depth of reasoning available at each layer must increase — not through unbounded autonomy, but through better evaluation harnesses, richer behavioral benchmarks, and a more complete integration with the data sources that give agents the context to reason accurately.

### 3.2 Trust at Scale

A platform deployed by one team at one organization is a useful tool. A platform trusted by hundreds of organizations in production is infrastructure. The gap between those two states is not feature work — it is the accumulated evidence that the platform behaves correctly, securely, and predictably across environments that differ significantly from each other.

Trust at scale requires:

- A public, independently audited security posture for the platform itself
- A behavioral evaluation record that is reproducible and published
- A vulnerability disclosure and response track record that demonstrates responsible stewardship
- An upgrade and deprecation model that organizations can rely on

These are commitments, not features. They require sustained investment from the maintainer community, and they are worth making explicitly because they are the precondition for Sentinel AI becoming infrastructure rather than a project.

### 3.3 Ecosystem Depth

The value of an AI security response platform is bounded by the breadth of its integrations. An agent that can reason about alerts but cannot query the identity system, the cloud API logs, the network flow records, and the endpoint telemetry is reasoning with one hand tied behind its back.

The integration model must evolve from the current approach — manually built adapters for specific tools — toward a documented, stable interface that enables the security community to build and contribute integrations independently. A rich ecosystem of production-quality integrations, maintained by the organizations that use them, is a stronger foundation than any integration the core team can build alone.

This is why the integration interface is designed as a first-class public API, not an internal implementation detail.

---

## 4. The Direction of Travel — v0.1 to v2.0

The milestones below extend the charter's roadmap (§14) with directional intent for the platform's evolution toward the vision stated above. These are not delivery commitments. They are the waypoints that indicate whether the project is moving toward the vision or away from it.

### v0.1 — Validated Triage

Single-agent alert triage with a policy engine, structured output, and audit log. The core thesis: an AI agent can triage a real security alert accurately enough and transparently enough to be trusted by a security analyst. The MVP exit criteria in the charter (§13) define done.

### v0.2 — Governed Response

Autonomous response for a bounded, high-confidence action set: workload isolation, credential revocation, IP block, ticket creation. Policy-gated authorization, strict one-action-per-token semantics, full response audit trail. The thesis: governed autonomous action is safer than unstructured human action under time pressure.

### v0.3 — Multi-Agent Investigation

Multi-agent coordination for incident investigation. Cross-source event correlation. Structured investigation artifact as a first-class output. The thesis: AI can reconstruct an incident timeline faster and more completely than a manual analyst pivot.

### v0.4 — Observability and Operations

OpenTelemetry-native telemetry. Standard dashboard templates. Operator runbooks. The platform must be operable by a team that did not build it.

### v0.5 — Replay and Behavioral Testing

Deterministic replay engine. Behavioral test harness. CI integration for regression detection. The thesis: agent behavior is testable, and a regression in agent quality is detectable before it reaches production.

### v1.0 — Production-Grade

High-availability deployment. Tamper-evident audit log with integrity verification. Independent security audit. Stable public API with deprecation policy. The platform can be adopted by an organization with a production security requirement.

### v1.x — Ecosystem Buildout

Compliance policy packs (NIST CSF, CIS Controls, SOC 2, ISO 27001 alignment). Stable integration API published as a community contract. Integration registry for community-contributed adapters. At this milestone, the platform's value is no longer defined solely by what the core team has built.

### v2.0 — Trusted Infrastructure

The platform is in production across a diverse enough set of organizations that behavioral benchmarks reflect real-world threat distributions. Federated governance for multi-organization deployments. Behavioral baselining from production history. The platform's track record of correct, auditable behavior in production is itself evidence of trustworthiness.

The long-term objective beyond v2.0 is convergence with the industry's incident response practice standards — not by defining a new standard, but by implementing the existing ones well enough that adopting Sentinel AI is equivalent to adopting the practice.

---

## 5. What We Refuse to Build

A vision document that does not state what is out of bounds is a wish list, not a direction. The following are deliberate exclusions. Each reflects a judgment about what Sentinel AI must not become in order to be what it is trying to be.

### We will not build a SIEM replacement

Sentinel AI's value is in reasoning over events, not in storing them. The data layer is not our problem to solve. We consume from SIEMs; we do not replace them. A Sentinel AI that becomes a data platform loses the focus and discipline that makes it trustworthy as a reasoning layer.

### We will not build offensive tooling

The platform is a defender's tool. Any capability that is primarily useful for unauthorized access, exploitation, or lateral movement is out of scope — permanently and without exception. The dual-use risk is not acceptable for a platform designed to be trusted in production security environments.

### We will not build "fully autonomous" security

The vision explicitly rules out removing human accountability from security decisions. There is no roadmap milestone at which Sentinel AI recommends removing human escalation paths, lowering confidence thresholds to near zero, or granting agents open-ended response authority. The governance framework is a permanent feature, not a phase to be deprecated as the system matures.

This is not a limitation. It is the design. An AI system that cannot be governed cannot be trusted. A security platform that cannot be trusted is not a security platform.

### We will not compromise auditability for performance

Every optimization proposal for the audit log, the reasoning trace, or the policy evaluation path is evaluated first against its impact on audit completeness. A system that drops audit events under load, abbreviates reasoning traces to reduce storage, or batches policy evaluations in ways that obscure individual decisions has traded its most important property for a marginal operational convenience. That trade will not be made.

### We will not build a closed platform

Open source is a functional requirement, not a distribution choice. A security platform that organizations cannot audit is one they cannot fully trust. The platform's source code, architecture documentation, threat model, and security audit results are public. If a component cannot be open because of a genuine security risk — a specific cryptographic secret, a specific vulnerability that is not yet patched — that is a time-limited exception with an explicit plan to resolve it, not a standing practice.

---

## 6. The Ecosystem Bet

The central long-term bet behind Sentinel AI is that **the security engineering community will build on a trustworthy, open foundation faster and more effectively than any single vendor can build a closed one**.

This bet has historical precedent. The tools that define modern security operations infrastructure — Suricata, osquery, Zeek, OpenTelemetry, Falco — are open. The organizations that adopted them early shaped their development. The organizations that built integrations with them contributed those integrations back to the commons. The platforms that are most embedded in the industry's practice are often the ones that were the most open to that kind of participation.

The bet is not that open source is a growth strategy. It is that open source is the only model under which a security platform can earn the kind of trust that production security operations require. Scrutiny is not a threat to a well-built security platform; it is the mechanism by which its trustworthiness is established.

For this bet to pay off, the project must make genuine contributions easy and worthwhile:

- **Integrations** must have a stable, documented API so that organizations can build them without reading core platform internals.
- **Policy packs** must be structured so that organizations can share starting-point policies without sharing sensitive operational details.
- **Behavioral benchmarks** must be composable so that organizations can add domain-specific test cases without forking the evaluation harness.
- **Security disclosures** must be handled in a way that demonstrates responsible stewardship — publicly, promptly, and with full attribution.

The ecosystem does not build itself. These are active investments the maintainer community commits to making.

---

## 7. How We Know We Are Succeeding

The vision in §2 is qualitative. The success metrics in the charter (§12) are operational — they measure the platform at one point in time against defined targets. What follows is the connecting layer: the signals that indicate the project is moving toward the vision rather than drifting away from it.

### The platform is used in production by organizations outside the founding team

A platform that exists only in the founding team's environment has not yet been validated against the diversity of real-world security estates. The first production adopter outside the founding team is a milestone. Ten is a signal. Fifty is early evidence of infrastructure status.

### Organizations contribute integrations they built for their own environments

When an organization invests in building a Sentinel AI integration for a data source or response target they use, and then contributes it back to the project, that is evidence that the integration API is stable enough to build on, the contribution process is accessible, and the organization trusts the platform enough to base operational tooling on it.

### Security researchers find and responsibly disclose vulnerabilities in the platform

This is a success signal, not a failure signal. A platform that attracts security research attention is a platform that is considered worth examining. A platform that handles disclosed vulnerabilities promptly and professionally builds the trust track record that production adoption requires.

### The behavioral evaluation record improves over time without regression

Each quarterly evaluation cycle either maintains or improves the platform's behavioral metrics across all agent roles. A regression in any blocking threshold (`agents/AGENTS.md` §§3.5, 4.5, 5.5, 6.6) is treated as a defect and resolved before the next evaluation cycle completes. The long-term trajectory of the evaluation record is the most honest measure of whether the platform is getting more trustworthy or less.

### The governance framework is not simplified away

As the platform matures, there will be pressure — from users who want faster time-to-action, from contributors who find the policy system complex, from adoption metrics that suggest governance is a friction point — to reduce the strictness of the governance framework. Resisting this pressure, while continuing to make governance easier to use, is the signal that the project has internalized the vision rather than just stated it.

---

*This document captures where Sentinel AI is trying to go and why. It is a strategic commitment from the maintainer community to the organizations that adopt the platform and the security engineers who contribute to it. When decisions about the platform's direction are unclear, return here.*
