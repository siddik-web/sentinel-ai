# Security — Sentinel AI

> **Document class:** Security posture and controls
> **Status:** Active
> **Scope:** Platform security — the security of Sentinel AI itself, not the security operations it enables
> **Derived from:** `PROJECT_CHARTER.md` §10 EP2, EP4, EP6, EP8; §9 PP4

---

## Table of Contents

1. [Purpose and Scope](#1-purpose-and-scope)
2. [Threat Model](#2-threat-model)
   - [2.1 Assets](#21-assets)
   - [2.2 Threat Actors](#22-threat-actors)
   - [2.3 Attack Surface and Attack Vectors](#23-attack-surface-and-attack-vectors)
   - [2.4 Trust Boundaries](#24-trust-boundaries)
3. [Data Classification](#3-data-classification)
4. [Authentication and Authorization](#4-authentication-and-authorization)
   - [4.1 RBAC Model](#41-rbac-model)
   - [4.2 Identity Provider Integration](#42-identity-provider-integration)
5. [Security Controls by Component](#5-security-controls-by-component)
6. [Supply Chain Security](#6-supply-chain-security)
7. [Vulnerability Management](#7-vulnerability-management)
8. [Security Disclosure Process](#8-security-disclosure-process)
9. [Incident Response](#9-incident-response)

---

## 1. Purpose and Scope

This document defines the security posture of the Sentinel AI platform itself. It covers the threat model, data classification, authorization model, component-level controls, and the processes for vulnerability management and security disclosure.

**In scope:** The security of the Sentinel AI runtime, its agents, its policy engine, its audit log, its integrations, and its supply chain.

**Out of scope:** The security operations that Sentinel AI enables for its adopters — threat detection, incident response, and SOAR-style automation. Those are product capabilities, not platform security controls.

**Relationship to ENGINEERING.md:** `docs/ENGINEERING.md` §9 defines *when* threat modeling and security review are invoked in the engineering lifecycle. This document defines *what* the threat model covers and *what* the security controls are.

A security platform that is itself insecure is worse than no security platform. An attacker who compromises Sentinel AI's governance layer gains the ability to suppress detection, trigger false autonomous responses, and access a complete record of an organization's security posture. The controls in this document exist because the platform's role makes it a high-value target.

---

## 2. Threat Model

### 2.1 Assets

Assets are ordered by the consequence of compromise. The ordering is deliberate: controls SHOULD be proportionally stronger for higher-consequence assets.

| Asset | Consequence of compromise |
|---|---|
| **Policy files** | Governance bypass — an attacker who controls policy controls what agents are permitted to do |
| **Audit log** | Evidence destruction or fabrication — tampered logs cannot be used for post-incident review or compliance audit |
| **Agent tool execution interface** | Arbitrary action execution — a compromised tool interface can invoke any permitted response action without policy authorization |
| **HITL escalation path** | Decisions made without human review — autonomous actions proceed where human approval was required |
| **Model provider credentials** | False or manipulated agent reasoning at scale; data exfiltration via prompt content |
| **Integration credentials** (SIEM, response targets) | Unauthorized data access or false response actions against production systems |
| **Alert and event data** | Intelligence disclosure — exposes an organization's detection coverage, undetected threats, and investigation history |
| **Agent reasoning traces** | Detection logic disclosure — reveals what the platform does and does not detect, enabling targeted evasion |
| **Deployment configuration** | Platform availability and behavior manipulation |

### 2.2 Threat Actors

**TA1 — External attacker (detection suppression)**
Goal: cause Sentinel AI to fail to detect or triage a real threat. Methods: adversarial alert payloads crafted to trigger false negatives, prompt injection in log data, policy file tampering via compromised CI pipeline.

**TA2 — External attacker (weaponized response)**
Goal: cause Sentinel AI to execute a harmful autonomous response. Methods: crafted alerts designed to trigger high-confidence false positives that result in workload isolation, credential revocation, or IP blocking as denial-of-service against production systems.

**TA3 — Insider threat**
Goal: suppress evidence of own activity, modify authorization, or exfiltrate intelligence. Methods: direct audit log modification, policy change to self-authorize elevated capabilities, unauthorized export of alert data or reasoning traces.

**TA4 — Supply chain attacker**
Goal: persistent access or behavioral manipulation at scale. Methods: compromised Python dependency, malicious integration adapter published to a package registry, poisoned model provider responses.

**TA5 — Adversarial inputs**
Goal: manipulate agent reasoning without compromising infrastructure. Methods: prompt injection embedded in log fields, alert metadata, or enrichment API responses; crafted event sequences designed to confuse multi-source correlation.

### 2.3 Attack Surface and Attack Vectors

The following maps attack vectors to the STRIDE categories they represent:

| Vector | STRIDE category | Primary threat actor |
|---|---|---|
| Prompt injection in ingested alert data | Tampering, Elevation of Privilege | TA1, TA5 |
| Policy file modification via compromised CI | Tampering | TA1, TA4 |
| Audit log deletion or modification | Tampering, Repudiation | TA1, TA3 |
| Model provider credential theft | Information Disclosure, Spoofing | TA4 |
| Crafted alert triggering false autonomous response | Denial of Service, Tampering | TA2 |
| Integration credential theft | Spoofing, Information Disclosure | TA4 |
| HITL notification interception or suppression | Repudiation, Denial of Service | TA3 |
| Compromised dependency with backdoor | All categories | TA4 |
| Insider modification of RBAC configuration | Elevation of Privilege | TA3 |
| Replay of stale policy against updated agent | Tampering, Elevation of Privilege | TA1 |

### 2.4 Trust Boundaries

A trust boundary is an interface where data crosses from a less-trusted to a more-trusted context. All data crossing a trust boundary MUST be validated. Trust is never assumed based on network location or transport security alone (charter EP4).

```
[ External event sources ]
         │
         │  ← Trust Boundary 1: Inbound event ingestion
         ▼
[ Integration adapters ]  ← validates schema, sanitizes fields
         │
         │  ← Trust Boundary 2: Internal event bus
         ▼
[ Triage / Investigation agents ]
         │  ← Trust Boundary 3: Agent → tool execution
         ▼
[ Tool execution interface ]  ← validates capability against policy
         │
         │  ← Trust Boundary 4: Policy engine decision
         ▼
[ Response actions / HITL / Audit log ]
         │
         │  ← Trust Boundary 5: Outbound integration
         ▼
[ Response targets (SIEM, ticketing, infrastructure APIs) ]
```

Model provider APIs, enrichment APIs, and threat intelligence feeds are external inputs. They are treated as untrusted data sources at Trust Boundary 3 regardless of the provider's reputation or the transport security in use.

---

## 3. Data Classification

All data processed, stored, or transmitted by Sentinel AI is assigned one of four classification tiers. The classification determines encryption requirements, access controls, retention limits, and logging obligations.

| Tier | Label | Examples | Minimum controls |
|---|---|---|---|
| **Tier 1** | RESTRICTED | Model API keys, SIEM integration tokens, response target credentials, private keys | Encrypted at rest and in transit; never logged in plaintext; access limited to the process that requires them; rotation supported and documented |
| **Tier 2** | SECURITY SENSITIVE | Alert payloads, investigation artifacts, reasoning traces, audit log entries, HITL escalation content, enrichment data | Encrypted at rest and in transit; access controlled by RBAC; configurable retention with enforced deletion; never transmitted to third parties outside declared integrations |
| **Tier 3** | INTERNAL | Policy files, agent definitions, deployment configuration, integration schemas | Version-controlled; access controlled by RBAC; changes audited |
| **Tier 4** | PUBLIC | Documentation, release artifacts, public API specifications, changelogs | No encryption requirement; no access control; integrity verification SHOULD be provided for release artifacts via signed checksums |

**Default classification:** Any data whose classification is ambiguous defaults to Tier 2 (SECURITY SENSITIVE) until explicitly reclassified by a maintainer.

**PII in alert data:** Alert payloads frequently contain personally identifiable information — usernames, email addresses, IP addresses, device identifiers. Tier 2 controls apply. Adopters are responsible for configuring retention policies that comply with applicable regulations. Sentinel AI MUST provide configurable retention and a documented deletion procedure.

---

## 4. Authentication and Authorization

### 4.1 RBAC Model

Sentinel AI uses role-based access control. Every capability — reading audit logs, authoring policies, approving HITL escalations, deploying agents, configuring integrations — is associated with one or more roles. Access is denied by default; roles grant access explicitly.

The minimum viable role set is defined below. Deployments MAY define additional roles but MUST NOT grant capabilities to roles beyond what is defined here without a documented justification.

| Role | Capabilities |
|---|---|
| **Platform Administrator** | All capabilities. Full CRUD on policies, agents, integrations, and RBAC configuration. Read and export audit logs. Approve HITL escalations. Deploy and retire agents. |
| **Policy Author** | Create, update, and deploy policy files. Read audit logs scoped to agents governed by their own policies. Cannot modify RBAC, deploy agents authored by others, or approve HITL escalations. |
| **Security Analyst** | Read triage outputs, investigation summaries, and full audit logs. Approve and reject HITL escalations. Cannot modify policies, deploy agents, or configure integrations. |
| **Integration Manager** | Configure inbound data sources and outbound response targets. Read integration health and connection status. Cannot read alert data, audit logs, or modify policies. |
| **Auditor** | Read-only access to audit logs, policy files, agent definitions, and execution history. No write access to any resource. |
| **Read-only Viewer** | View dashboards, triage summaries, and platform health metrics. Cannot read raw alert data, audit logs, or policy files. |

**Least privilege applies at deployment time.** An operator deploying Sentinel AI MUST assign the minimum role required for each service account, integration, and human user. Platform Administrator MUST NOT be the default role for any automated process.

### 4.2 Identity Provider Integration

Sentinel AI MUST support integration with external identity providers via standard protocols (OIDC and SAML 2.0 as minimum requirements). Local credential management is available for development environments only; production deployments SHOULD use an external identity provider.

Service-to-service authentication for integrations MUST use short-lived credentials with a documented rotation procedure. Long-lived static API keys for integrations are permitted only with a written justification and a defined rotation schedule.

---

## 5. Security Controls by Component

The sensitive code areas listed in `docs/ENGINEERING.md` §9.3 require security review for any change. This section describes the security controls that must be maintained for each.

### 5.1 Policy Engine

The policy engine is the primary enforcement point for agent governance. A bypass here is a critical vulnerability.

- Policy files MUST be validated against a strict schema before loading. Malformed policy files MUST cause the engine to reject the policy and alert — not fall back to a permissive default.
- The policy evaluator MUST be isolated from agent code. An agent cannot influence the policy evaluation of its own actions at runtime.
- Policy files are Tier 3 (INTERNAL) data. Write access is restricted to the Policy Author and Platform Administrator roles. Changes are version-controlled and audited.
- The policy engine MUST fail closed: if evaluation produces an error or ambiguous result, the action is denied and the error is logged.

### 5.2 Audit Log

The audit log is tamper-evident by cryptographic hash chaining (defined in `PROJECT_CHARTER.md` §15 Glossary). It is the evidentiary record for post-incident review and compliance audit.

- The audit log write path exposes no delete, update, or truncate operation. Append is the only permitted write operation.
- Each log entry includes the hash of the previous entry. Chain integrity can be verified independently.
- Log entries are Tier 2 (SECURITY SENSITIVE). Read access is restricted to Security Analyst, Auditor, and Platform Administrator roles.
- Log entries MUST be written before the action they record is executed. A system failure between log write and action execution is acceptable; a system failure that executes an action without logging it is not.
- The audit log storage backend MUST support at-rest encryption and configurable retention with enforced deletion.

### 5.3 Agent Tool Execution Interface

The tool execution interface is the boundary at which agents interact with external systems.

- Tool calls MUST be evaluated against the policy engine before execution. A tool call that has not been explicitly authorized by the applicable policy MUST be denied.
- Tool outputs are untrusted external data (Trust Boundary 3). They MUST be validated against the declared output schema before being returned to the agent.
- Tools MUST execute with timeouts. A tool that does not return within the configured timeout is treated as a failure; the failure is logged and the agent is notified.
- The set of available tools is declared at deployment time and cannot be extended by agent code at runtime.

### 5.4 HITL State Machine

The HITL system manages agent execution state while awaiting human review. State corruption here means either an agent proceeding without human approval or an escalation that never reaches a human.

- HITL state MUST be durable — it MUST survive process restarts without loss.
- Escalation notifications MUST be delivered with confirmation. An undelivered notification is a platform failure, not an acceptable degraded state.
- The HITL approval interface is accessible only to Security Analyst and Platform Administrator roles.
- A HITL timeout (operator-configurable) MUST result in a defined fallback behavior declared in the applicable policy — not a default-proceed.

### 5.5 External Integration Adapters

Integration adapters are the inbound and outbound interfaces to the organization's existing tooling.

- Inbound adapters MUST validate all incoming event data against the declared integration schema before passing events to the internal event bus. Events that fail validation are rejected and logged; they MUST NOT reach the triage agent in an unvalidated state.
- Outbound adapters MUST enforce the action allowlist defined in the applicable policy. An outbound call not covered by the policy MUST be blocked.
- Integration credentials are Tier 1 (RESTRICTED). They MUST NOT appear in logs, traces, error messages, or the audit log in plaintext.
- Adapter code changes require Stage 6 (Security Review) as specified in `docs/ENGINEERING.md` §9.3.

---

## 6. Supply Chain Security

Sentinel AI's dependency supply chain is a primary attack surface (Threat Actor TA4). A compromised dependency has the same access as the platform process itself.

**Dependency pinning:** All direct and transitive dependencies MUST be pinned to exact versions with verified checksums. The lockfile is a first-class security artifact; unpinned dependencies are a blocking CI finding. (See `docs/ENGINEERING.md` §4.3.)

**Software Bill of Materials (SBOM):** An SBOM in CycloneDX or SPDX format MUST be generated and published with every release. Adopters use the SBOM for their own dependency risk assessments.

**Vulnerability scanning:** Dependencies are scanned for known CVEs on every CI run and on a weekly automated schedule. New critical or high CVEs in direct dependencies are blocking findings with a 14-day remediation window (aligned with `PROJECT_CHARTER.md` §12). Accepted exceptions are documented in `docs/security-exceptions/` with a time bound.

**Release artifact integrity:** Every release artifact MUST be signed. Adopters MUST be able to verify artifact integrity before deployment. The signing key management process is documented in `docs/RELEASING.md`.

**Contributor verification:** Pull requests from new contributors are reviewed before CI executes on their code. Automated execution of untrusted contributor code without maintainer review is PROHIBITED.

---

## 7. Vulnerability Management

### Discovery

Vulnerabilities in Sentinel AI may be discovered through: automated dependency scanning (continuous), security testing in the engineering lifecycle (`docs/ENGINEERING.md` §7.5), independent security audit (required before v1.0), external security research (§8), and penetration testing (required before v1.0).

### Classification

Vulnerabilities are classified using the CVSS v3.1 scoring system:

| Severity | CVSS Score | Response SLA |
|---|---|---|
| Critical | 9.0–10.0 | Patch within 7 days; immediate advisory to known adopters |
| High | 7.0–8.9 | Patch within 14 days; advisory in release notes |
| Medium | 4.0–6.9 | Patch within 90 days; documented in changelog |
| Low | 0.1–3.9 | Addressed at next scheduled release |
| Informational | N/A | Documented; no patch required |

SLA timers begin from the date the vulnerability is confirmed by a maintainer, not from the date it was reported. The clock does not pause during holidays or release cycles.

### Disclosure

Sentinel AI follows a coordinated disclosure model. The process is defined in §8. Public disclosure MUST NOT occur before a patch is available and adopters have been given reasonable time to upgrade (minimum 7 days for critical, 14 days for high).

---

## 8. Security Disclosure Process

Sentinel AI takes security disclosures seriously. The platform is security infrastructure; vulnerabilities in it can affect the security posture of every organization that depends on it.

### How to Report

Security vulnerabilities MUST be reported privately. Do not open a public GitHub Issue for a security vulnerability.

**Contact:** `security@sentinel-ai.dev`  
*(Replace with the actual address before first public release.)*

Reports MUST include:
- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Potential impact assessment (as the researcher understands it)
- Whether the researcher intends to publish

PGP encryption is available for reports that require it. The public key is published at `/security.txt` and in the repository root.

### Response Commitments

| Action | Timeline |
|---|---|
| Acknowledge receipt | Within 48 hours |
| Confirm or dispute the vulnerability | Within 7 days |
| Provide a patch timeline | Within 14 days of confirmation |
| Notify the reporter before public disclosure | At least 7 days in advance |

These are commitments, not aspirations. Failure to meet them is a process failure that MUST be reviewed by the maintainer council.

### Scope

**In scope for this disclosure process:**
- Vulnerabilities in the Sentinel AI codebase
- Vulnerabilities in official release artifacts
- Vulnerabilities in the reference deployment configuration

**Out of scope:**
- Vulnerabilities in third-party dependencies — report those to the dependency maintainer; we will track remediation
- Social engineering of maintainers
- Denial-of-service attacks that require physical access or insider credentials

### Recognition

Researchers who report valid, confirmed vulnerabilities will be acknowledged in the release notes for the fixing release, unless they prefer not to be named.

---

## 9. Incident Response

This section covers incidents affecting the Sentinel AI platform itself — not incidents that Sentinel AI's agents are responding to on behalf of adopters.

### Incident Categories

| Category | Definition | Example |
|---|---|---|
| **Platform compromise** | Unauthorized access to the Sentinel AI runtime, policy files, or audit log | Supply chain attack, credential theft |
| **Audit log integrity failure** | Evidence of audit log tampering or gap | Missing entries, broken hash chain |
| **Policy bypass** | Agent action executed without policy authorization | Tool call executed despite explicit deny rule |
| **Governance failure** | HITL escalation not delivered; agent proceeding past a required human checkpoint | Notification delivery failure with no fallback |
| **Credential exposure** | Tier 1 (RESTRICTED) data appearing in logs, traces, or error messages | API key in log output |

### Response Steps

1. **Detect and scope.** Identify the affected component, the time window, and the data or systems involved.
2. **Contain.** Isolate the affected component. Revoke compromised credentials. Disable affected agents if policy integrity cannot be confirmed.
3. **Preserve evidence.** Do not delete or modify logs. Export and sign the current audit log state before any remediation.
4. **Notify.** For Platform Compromise and Audit Log Integrity Failure: notify known adopters within 24 hours of confirmation. Include the scope, the data potentially affected, and the remediation steps available.
5. **Remediate.** Apply the fix. Verify the fix restores integrity before re-enabling affected components.
6. **Review.** Conduct a post-incident review within 14 days. Identify root cause, contributing factors, and process changes. Publish a public post-mortem for incidents that affected adopters unless doing so would create additional risk.

### Notification Contact

Adopters who want to receive security notifications MUST register at *(registration mechanism to be defined before first release)*. Notifications are sent before public disclosure for critical and high severity incidents.

---

*Amendments to this document require an entry in `.ai/decisions/` and review by the maintainer council. Changes to the threat model, RBAC role definitions, or data classification tiers are load-bearing security decisions — they affect every component and every adopter. They are not made unilaterally.*
