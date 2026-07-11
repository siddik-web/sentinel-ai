# ADR-001 — Adopt OCSF as the Canonical Event Schema

> **Status:** Accepted
> **Date:** 2026-07-01
> **Deciders:** Sentinel AI maintainer team
> **Informed:** Security Engineers, Integration Authors, AI/ML Engineers

---

## Context

Sentinel AI ingests security events from heterogeneous sources — SIEMs, EDR platforms, identity providers, cloud APIs, network monitoring tools, and custom webhooks. Each source produces events in its own schema. Before an agent can reason over an event, the platform must normalize it into a common representation.

The normalization layer is a load-bearing architectural decision. The schema chosen here:

- Determines the shape of every agent's input interface
- Constrains what fields agents can reference in reasoning and policy
- Defines what integration authors must map to when building data source adapters
- Sets the long-term compatibility surface for behavioral test fixtures

The options evaluated were:

| Option | Description |
|---|---|
| **OCSF (Open Cybersecurity Schema Framework)** | Open standard developed by a coalition of security vendors (AWS, Splunk, IBM, CrowdStrike, and others). Versioned, extensible class hierarchy covering the full event taxonomy relevant to security operations. |
| **ECS (Elastic Common Schema)** | Elastic's field naming standard, designed primarily for Elasticsearch ingestion. Broad adoption among Elastic stack users; less adopted outside that ecosystem. |
| **STIX/TAXII** | Structured Threat Information Expression — designed for threat intelligence sharing, not operational event normalization. Too narrow for this use case. |
| **Custom schema** | Design and maintain a Sentinel AI-specific internal schema. Full control; no external governance dependency. |

---

## Decision

**Adopt OCSF as the canonical internal event schema for all agent inputs.**

All data source integrations MUST map incoming events to OCSF before they are passed to any agent. All agent input contracts use OCSF-typed fields. Policy files reference OCSF field paths. Behavioral test fixtures are OCSF-formatted.

---

## Rationale

### Why OCSF over ECS

ECS has broader current adoption in Elastic deployments, but OCSF has broader cross-vendor governance. The OCSF schema is designed for interoperability across security tooling stacks, not for one vendor's storage and search system. Sentinel AI is explicitly designed as a cross-stack reasoning layer (`PROJECT_CHARTER.md` §5, §7 non-goal: "Replacing a SIEM"). Adopting ECS would create an implicit dependency on Elastic ecosystem conventions in a platform that must be vendor-neutral.

OCSF also has a more formal class hierarchy that maps cleanly to the event types agents need to reason about: Authentication, Network Activity, API Activity, File System Activity, Process Activity, Finding. ECS is a flat field namespace; OCSF is a typed taxonomy.

### Why OCSF over custom schema

A custom schema would give us full control over field names, types, and evolution. It would also require:

- A full taxonomy design effort at a point where the team has no comparative advantage over standards bodies who have already done this work
- Integration authors to learn a Sentinel AI-specific schema rather than an industry standard
- Ongoing governance of the schema itself as an internal standard

The integration tax (`PROJECT_CHARTER.md` §4.5) is one of the core problems Sentinel AI is trying to reduce. Requiring integration authors to map to a proprietary schema increases that tax. Mapping to OCSF allows integration authors to reuse existing OCSF mappings that security vendors are already producing.

### Why OCSF over STIX/TAXII

STIX is designed for threat intelligence sharing — indicators of compromise, attack patterns, campaigns. It does not cover the operational event types (authentication events, process executions, network flows) that constitute the majority of agent inputs. This is not the right tool for this problem.

---

## Consequences

### Positive

- Integration authors can reference OCSF documentation and existing OCSF mappings from major vendors rather than reading Sentinel AI internals
- Agent input schemas are self-documenting — OCSF field names and class definitions are publicly available
- Behavioral test fixtures are portable: any OCSF-compliant event from any source is a valid test input with no transformation required
- Policy files that reference OCSF fields work across all data sources that produce the same event class
- OCSF is versioned; the platform can adopt new OCSF versions through a defined upgrade path

### Negative / Accepted Trade-offs

- OCSF has a learning curve for contributors unfamiliar with it; requires documentation pointing to OCSF resources
- OCSF does not cover every field every source produces; extension fields are needed for source-specific context. Extension fields MUST follow the OCSF extension pattern (`unmapped` namespace) and MUST NOT be referenced in agent reasoning without explicit documentation
- OCSF is an evolving standard; schema version transitions require integration migrations. The platform MUST pin to a specific OCSF version in all integration contracts and increment that version explicitly
- Some alert sources produce highly proprietary payloads that map poorly to OCSF classes; those fields are preserved in `unmapped` and flagged in integration documentation as requiring analyst review

### Constraints this decision imposes

- All data source integrations MUST emit OCSF-conformant events before handing off to the platform ingestion layer
- Agent input schemas MUST use OCSF field paths wherever a corresponding OCSF field exists
- Policy files MUST reference OCSF field paths; references to raw source-specific fields are not permitted
- The platform MUST declare the OCSF version it targets in a versioned contract; upgrades to a new OCSF version are a minor version bump for affected integrations
- Integration test suites MUST include OCSF schema validation as a required step

---

## Alternatives Rejected

| Alternative | Rejection reason |
|---|---|
| ECS | Elastic-centric; less suitable for a vendor-neutral cross-stack platform |
| Custom schema | Increases integration tax; requires maintaining a schema standard in addition to a platform |
| Multiple schemas, per source | Eliminates the normalization benefit entirely; agents would need source-aware logic |
| STIX/TAXII | Wrong scope — threat intelligence, not operational event normalization |

---

## References

- OCSF specification: https://schema.ocsf.io
- OCSF GitHub: https://github.com/ocsf/ocsf-schema
- `PROJECT_CHARTER.md` §4.5 (Integration Tax), §7 (Non-Goals)
- `docs/SECURITY.md` §2 (Data Classification) — data classification tiers apply to OCSF event fields
