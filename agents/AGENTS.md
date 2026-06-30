# Agents — Sentinel AI

> **Document class:** Agent specifications
> **Status:** Active
> **Derived from:** `PROJECT_CHARTER.md` §6 (G1–G4), §11 (AP1–AP7)
> **Depends on:** `.ai/AI_PRINCIPLES.md` (confidence model, evaluation framework, trace schema)
> **Resolves stubs in:** `docs/ENGINEERING.md` §7.4, §8.3

---

## Table of Contents

1. [Purpose and Scope](#1-purpose-and-scope)
2. [Agent Role Taxonomy](#2-agent-role-taxonomy)
3. [Triage Agent](#3-triage-agent)
4. [Investigation Agent](#4-investigation-agent)
5. [Response Agent](#5-response-agent)
6. [Orchestration Agent](#6-orchestration-agent)
7. [Inter-Agent Communication](#7-inter-agent-communication)
8. [Human-in-the-Loop Integration](#8-human-in-the-loop-integration)
9. [Agent Lifecycle](#9-agent-lifecycle)

---

## 1. Purpose and Scope

This document specifies the four agent roles in Sentinel AI: their purpose, capability sets, input and output contracts, policy structure, failure modes, and per-role evaluation thresholds.

**This document governs:** agent role definitions, capability boundaries, interface contracts, inter-agent communication rules, HITL integration, and the agent lifecycle (deployment, versioning, retirement).

**This document does not govern:** the evaluation methodology (`.ai/AI_PRINCIPLES.md` §9), the security controls on agent execution (`docs/SECURITY.md` §5), or the engineering process for making changes to agent logic (`docs/ENGINEERING.md` §3).

**Relationship to evaluation stubs:** The per-role thresholds in §§3–6 of this document provide the role-specific evaluation data deferred in `docs/ENGINEERING.md` §7.4 and §8.3. Platform baseline thresholds from `.ai/AI_PRINCIPLES.md` §9.4 apply to all roles. Where this document specifies a stricter threshold, this document governs.

---

## 2. Agent Role Taxonomy

Sentinel AI defines four agent roles with distinct, non-overlapping capability sets enforced by the policy engine. Role boundaries are not advisory — they are enforced at runtime. An agent cannot assume capabilities beyond its declared role.

| Role | Charter goal | Primary output | Response authority |
|---|---|---|---|
| **Triage Agent** | G1 | Severity classification + recommended action | None |
| **Investigation Agent** | G2 | Investigation timeline + entity graph | None |
| **Response Agent** | G3 | Execution record of an authorized action | Defined action set only |
| **Orchestration Agent** | G4 | Workflow execution record + HITL summaries | None directly |

**Capability separation is the foundational security property of the agent model.** An agent that reads alerts cannot execute response actions. An agent that executes response actions cannot query raw data sources. An agent that orchestrates cannot take direct action. This separation ensures that a compromised or manipulated agent in any one role cannot unilaterally complete a full attack-to-response cycle.

---

## 3. Triage Agent

### 3.1 Role Definition

The Triage Agent is the entry point for all incoming alerts. It evaluates a single alert against enrichment context and produces a structured triage output. It is the highest-volume agent in the system and the most frequent target for adversarial inputs.

**Owner accountability:** Every deployed Triage Agent instance MUST declare an owner per `.ai/AI_PRINCIPLES.md` §3.

### 3.2 Capabilities

**Permitted tools:**

| Tool | Operation | Scope |
|---|---|---|
| `asset_lookup` | Read | Asset metadata for IPs, hostnames, users, and workloads named in the alert |
| `threat_intel_query` | Read | Threat intelligence for indicators present in the alert |
| `alert_history_query` | Read | Historical alerts for the same asset or indicator, scoped to a configurable lookback window |
| `enrichment_fetch` | Read | Contextual enrichment from declared enrichment sources |

**Prohibited (absolute):**
- Response actions of any kind
- Writing to any external system
- Querying data sources not listed above
- Delegating to or spawning other agents
- Accessing investigation artifacts from other sessions

### 3.3 Interface Contract

**Input schema:**

```json
{
  "alert": {
    "id":          "string",
    "source":      "string",
    "received_at": "ISO8601",
    "payload":     { }
  },
  "context": {
    "asset_ids":   ["string"],
    "session_id":  "string",
    "policy_ref":  "string"
  }
}
```

**Output schema:**

```json
{
  "triage_id":    "string",
  "alert_id":     "string",
  "severity":     "low | medium | high | critical",
  "confidence":   { },
  "verdict":      "true_positive | false_positive | undetermined",
  "recommended_action": {
    "category":   "investigate | escalate | respond | dismiss",
    "rationale":  "string"
  },
  "trace_id":     "string",
  "completed_at": "ISO8601"
}
```

The `confidence` field MUST conform to the schema in `.ai/AI_PRINCIPLES.md` §4.1. The `trace_id` MUST reference a fully written reasoning trace before the output is returned.

### 3.4 Failure Modes

| Failure condition | Required behavior |
|---|---|
| Enrichment tool timeout | Proceed with available context; note gap in reasoning trace; lower confidence tier by one level |
| Threat intel query returns no results | Treat as neutral signal; do not assume benign; document in trace |
| Input fails schema validation | Reject the alert; log the rejection with the validation error; escalate the raw alert to HITL |
| Reasoning produces no confident verdict | Emit `verdict: undetermined`, `confidence_tier: low`; do not default to benign |
| Agent process fails mid-execution | HITL escalation with raw alert; partial trace discarded; execution gap logged |

The Triage Agent MUST NOT silently emit a low-confidence triage as if it were high-confidence. An uncertain agent says so.

### 3.5 Evaluation Thresholds

These thresholds extend the platform baselines from `.ai/AI_PRINCIPLES.md` §9.4. Where a threshold here is stricter, this document governs.

| Dimension | Threshold | Rationale |
|---|---|---|
| Standard fixture accuracy | ≥ 85% | Platform baseline |
| Adversarial fixture accuracy | ≥ 92% | Triage is the primary adversarial input surface |
| False positive rate | ≤ 5% | Platform baseline |
| False negative rate | ≤ 3% | Tighter than baseline — a missed true positive is a detection failure |
| Reasoning trace completeness | 100% | Platform baseline |
| Policy compliance | 100% | Platform baseline |

---

## 4. Investigation Agent

### 4.1 Role Definition

The Investigation Agent performs deep multi-source correlation for confirmed or suspected incidents. It operates on a directive from the Orchestration Agent and produces a structured investigation artifact — a timeline, entity graph, and response recommendation — not a chat summary.

**Owner accountability:** Every deployed Investigation Agent instance MUST declare an owner per `.ai/AI_PRINCIPLES.md` §3.

### 4.2 Capabilities

**Permitted tools:**

| Tool | Operation | Scope |
|---|---|---|
| `siem_search` | Read | Full-text and structured search over SIEM event data |
| `identity_log_query` | Read | Authentication events, privilege changes, session activity |
| `network_log_query` | Read | Network flow records, DNS queries, proxy logs |
| `cloud_api_activity_query` | Read | Cloud provider API call logs (IAM, storage, compute) |
| `alert_history_query` | Read | All alerts in the investigation window for related assets |
| `asset_lookup` | Read | Asset metadata and relationship graph |
| `threat_intel_query` | Read | Threat intelligence for all indicators in the investigation |
| `investigation_artifact_write` | Write | Write findings to the investigation artifact store |

**Prohibited (absolute):**
- Response actions of any kind
- External communications (email, webhook, notification)
- Spawning parallel investigations without Orchestration Agent authorization
- Writing to any system other than the investigation artifact store

### 4.3 Interface Contract

**Input schema:**

```json
{
  "investigation_id": "string",
  "directive": {
    "scope":       "string",
    "start_time":  "ISO8601",
    "end_time":    "ISO8601",
    "seed_alerts": ["string"],
    "seed_assets": ["string"]
  },
  "context": {
    "session_id":  "string",
    "policy_ref":  "string"
  }
}
```

**Output schema:**

```json
{
  "investigation_id":  "string",
  "status":            "complete | partial | failed",
  "timeline": [
    {
      "timestamp":     "ISO8601",
      "event_type":    "string",
      "description":   "string",
      "source":        "string",
      "entity_ids":    ["string"]
    }
  ],
  "entities": [
    {
      "id":            "string",
      "type":          "user | asset | ip | process | file",
      "role":          "victim | attacker | lateral | unknown",
      "evidence_refs": ["string"]
    }
  ],
  "response_recommendation": {
    "category":        "contain | remediate | monitor | escalate",
    "confidence":      { },
    "rationale":       "string"
  },
  "coverage_gaps": ["string"],
  "trace_id":          "string",
  "completed_at":      "ISO8601"
}
```

When `status` is `partial`, `coverage_gaps` MUST be populated describing which sources could not be queried and why. A partial investigation result with documented gaps is always preferable to a failed investigation with no output.

### 4.4 Failure Modes

| Failure condition | Required behavior |
|---|---|
| One or more data sources unavailable | Continue with available sources; document gaps in `coverage_gaps`; do not fail the investigation |
| Investigation window returns no events | Return `status: complete` with empty timeline; document the negative result explicitly in the trace |
| Scope too broad to complete in time budget | Return `status: partial` with results to date; document the truncation boundary |
| Conflicting evidence with no clear resolution | Document both interpretations in the timeline; lower confidence; flag for HITL |
| Agent process fails mid-execution | Persist the investigation artifact in its current state as `status: partial`; escalate to HITL |

### 4.5 Evaluation Thresholds

| Dimension | Threshold | Rationale |
|---|---|---|
| Standard fixture accuracy | ≥ 88% | Higher than baseline — investigation outputs inform response decisions |
| Adversarial fixture accuracy | ≥ 90% | Platform baseline |
| False positive rate | ≤ 5% | Platform baseline |
| Reasoning trace completeness | 100% | Platform baseline |
| Policy compliance | 100% | Platform baseline |
| Source coverage | ≥ 75% of declared relevant sources queried | Investigation completeness metric — partial coverage must be documented |

---

## 5. Response Agent

### 5.1 Role Definition

The Response Agent executes a single authorized response action against a target system. It is the only agent with write authority over external systems. It operates exclusively on an explicit authorization token from the Orchestration Agent. It does not investigate, correlate, or triage — it acts and records.

**Owner accountability:** The Response Agent has the highest consequence of any role. Its owner MUST be a named individual, not a team identifier.

### 5.2 Capabilities

The Response Agent's action set is a closed list. No action outside this list may be executed regardless of policy content.

**Permitted actions:**

| Action | Target | Reversibility |
|---|---|---|
| `isolate_workload` | Compute instance, container | Reversible — isolation can be lifted |
| `revoke_credential` | User credential, service account token | Partially reversible — new credential must be issued |
| `block_network_indicator` | IP address, CIDR range, domain | Reversible — block can be removed |
| `create_ticket` | Ticketing system | Irreversible — creates a record |
| `notify_operator` | Notification channel | Irreversible — notification is sent |

**Permitted reads:**

| Tool | Scope |
|---|---|
| `incident_context_read` | Read-only access to the incident record authorizing this action |

**Prohibited (absolute):**
- Any query of raw data sources (SIEM, logs, identity, network)
- Executing more than one action per authorization token
- Chaining actions (the output of one action cannot become the input trigger for another within the same execution)
- Writing to the investigation artifact store
- Executing an action not in the permitted action list above

### 5.3 Interface Contract

**Input schema:**

```json
{
  "authorization": {
    "token":          "string",
    "issued_by":      "string",
    "incident_id":    "string",
    "action":         "string",
    "target":         { },
    "expires_at":     "ISO8601"
  },
  "context": {
    "session_id":     "string",
    "policy_ref":     "string"
  }
}
```

The `authorization.action` MUST exactly match one of the permitted actions in §5.2. The Response Agent MUST validate the authorization token before execution. An expired or invalid token is a hard stop — no action is attempted.

**Output schema:**

```json
{
  "execution_id":    "string",
  "authorization_token": "string",
  "action":          "string",
  "target":          { },
  "status":          "success | failed | rejected",
  "rejection_reason":"string | null",
  "executed_at":     "ISO8601 | null",
  "evidence": {
    "confirmation":  "string",
    "source":        "string"
  },
  "trace_id":        "string"
}
```

### 5.4 Failure Modes

| Failure condition | Required behavior |
|---|---|
| Authorization token expired | `status: rejected`; log with expiry time; escalate to HITL for re-authorization |
| Authorization token does not match policy | `status: rejected`; log policy mismatch; escalate to HITL |
| Target system unavailable | `status: failed`; log target unreachability; do NOT retry automatically; escalate to HITL |
| Action partially executed (e.g., credential revoked but session not terminated) | Log partial execution with explicit scope; escalate to HITL with description of what was and was not completed |
| Agent process fails after action is sent but before confirmation is received | Treat as unknown state; log as `status: unknown`; require human verification before next action |

The Response Agent MUST NOT retry a failed action automatically. Every retry requires a new authorization token. This prevents double-execution of irreversible actions.

### 5.5 Evaluation Thresholds

| Dimension | Threshold | Rationale |
|---|---|---|
| Standard fixture accuracy | ≥ 85% | Platform baseline |
| Adversarial fixture accuracy | ≥ 95% | Highest bar — unauthorized response actions cause direct harm |
| Authorization validation accuracy | 100% | Any failure to reject an invalid token is a critical security defect |
| Action execution accuracy | ≥ 99% | Aligned with charter §12 success metric |
| Reasoning trace completeness | 100% | Platform baseline |
| Policy compliance | 100% | Platform baseline |

---

## 6. Orchestration Agent

### 6.1 Role Definition

The Orchestration Agent coordinates the end-to-end workflow from incoming alert to resolved action. It is the only agent that can initiate HITL escalation, delegate to other agents, and authorize the Response Agent. It does not directly query data sources or execute response actions.

**Owner accountability:** Every Orchestration Agent instance MUST declare an owner per `.ai/AI_PRINCIPLES.md` §3. The owner is accountable for the full workflow, not just the orchestration layer.

### 6.2 Capabilities

**Permitted operations:**

| Operation | Description |
|---|---|
| `delegate_triage` | Invoke the Triage Agent with an alert input |
| `delegate_investigation` | Invoke the Investigation Agent with an investigation directive |
| `authorize_response` | Issue an authorization token to the Response Agent for a specific action |
| `initiate_hitl` | Pause workflow and escalate to a human operator |
| `resume_workflow` | Resume a paused workflow after HITL resolution |
| `workflow_state_write` | Write workflow execution state to the durable state store |

**Prohibited (absolute):**
- Direct queries of any data source
- Direct execution of response actions
- Authorizing a response action without a completed triage or investigation artifact
- Issuing more than one authorization token per incident per response category without HITL re-authorization

### 6.3 Interface Contract

**Input schema:**

```json
{
  "trigger": {
    "type":         "new_alert | hitl_resolution | manual",
    "alert_id":     "string | null",
    "resolution":   { }
  },
  "workflow_state_ref": "string | null",
  "context": {
    "session_id":   "string",
    "policy_ref":   "string"
  }
}
```

**Output schema:**

```json
{
  "workflow_id":     "string",
  "status":          "completed | paused_hitl | failed",
  "stages_executed": ["string"],
  "triage_ref":      "string | null",
  "investigation_ref":"string | null",
  "response_ref":    "string | null",
  "hitl_summary":    { },
  "trace_id":        "string",
  "completed_at":    "ISO8601"
}
```

### 6.4 Authorization Gate

Before the Orchestration Agent MAY issue a Response Agent authorization token, all of the following MUST be true:

1. A completed triage output exists for the triggering alert.
2. The triage confidence tier is High (≥0.85) OR an Investigation Agent output exists and its response recommendation confidence tier is High.
3. The requested action is within the Response Agent's permitted action list (§5.2).
4. The action is permitted by the applicable policy for the current severity and confidence level.
5. No active HITL escalation exists for this incident.

If any condition is not met, the Orchestration Agent MUST initiate HITL rather than proceeding autonomously.

### 6.5 Failure Modes

| Failure condition | Required behavior |
|---|---|
| Delegated agent returns an error | Log the error with full context; initiate HITL with the partial workflow state |
| Workflow state cannot be persisted | Halt the workflow; log the persistence failure; initiate HITL — do not proceed on ephemeral state |
| HITL notification delivery fails | Retry delivery up to 3 times with exponential backoff; if all fail, log a platform alert; halt further autonomous action |
| Authorization gate condition not met | Initiate HITL; log which condition failed and why |
| Process fails with in-flight HITL escalation | Workflow state is durable — resume on restart; re-deliver HITL notification if delivery status is unknown |

### 6.6 Evaluation Thresholds

| Dimension | Threshold | Rationale |
|---|---|---|
| Standard fixture accuracy | ≥ 85% | Platform baseline |
| Adversarial fixture accuracy | ≥ 90% | Platform baseline |
| Delegation accuracy | ≥ 95% | Correct agent invoked for the task |
| HITL delivery rate | 100% | Aligned with charter §12 — no dropped escalations |
| Authorization gate accuracy | 100% | Any incorrect token issuance is a critical security defect |
| Workflow state integrity | 100% | Lost workflow state is a platform reliability failure |
| Reasoning trace completeness | 100% | Platform baseline |
| Policy compliance | 100% | Platform baseline |

---

## 7. Inter-Agent Communication

Sentinel AI uses a **hierarchical orchestration model**. The Orchestration Agent is the sole coordinator; agents do not communicate with each other directly.

### Communication Rules

- All agent invocations are initiated by the Orchestration Agent. Triage, Investigation, and Response agents MUST NOT invoke each other or invoke the Orchestration Agent.
- Communication between agents is structured — typed input and output schemas (defined in §§3–6). Free-form message passing between agents is PROHIBITED.
- Every agent invocation is logged in the audit log with: the invoking agent, the invoked agent, the input schema version, and the session identifier.
- The Orchestration Agent is responsible for passing relevant outputs from one stage as inputs to the next. Agents do not share a common state store — all context flows through the Orchestration Agent.

### Session Model

All agents operating on a single alert or incident share a `session_id`. The session is created by the Orchestration Agent when a workflow begins and closed when the workflow completes or is retired. All audit log entries, reasoning traces, and artifacts are tagged with the session identifier to enable full reconstruction of a workflow.

---

## 8. Human-in-the-Loop Integration

HITL is a first-class feature (charter PP3), not a fallback. The Orchestration Agent is the sole entry point for HITL escalation.

### 8.1 HITL Trigger Conditions

The Orchestration Agent MUST initiate HITL when any of the following conditions are met:

| Condition | Trigger source |
|---|---|
| Triage confidence tier is Low (< 0.60) | Triage Agent output |
| Triage confidence tier is Medium and the recommended action is `respond` | Triage Agent output |
| Investigation confidence tier is Medium or Low | Investigation Agent output |
| Alert severity is Critical, regardless of confidence | Policy rule |
| Authorization gate condition is not met | Orchestration Agent logic |
| Any agent returns an error or partial result | Agent failure |
| Policy explicitly requires human review for this alert type | Policy rule |

### 8.2 HITL Escalation Payload

The escalation payload delivered to the human operator MUST include:

```json
{
  "hitl_id":          "string",
  "workflow_id":      "string",
  "escalation_reason":"string",
  "decision_needed":  "string",
  "context_summary":  "string",
  "triage_output":    { },
  "investigation_output": { },
  "recommended_options": [
    {
      "label":        "string",
      "action":       "string",
      "consequence":  "string"
    }
  ],
  "expires_at":       "ISO8601",
  "escalated_at":     "ISO8601"
}
```

The `decision_needed` field MUST be a specific question, not a summary. The `recommended_options` MUST enumerate the available choices with their consequences. A human operator receiving this payload should be able to make a decision without needing to query additional systems.

### 8.3 HITL State and Resume

- Workflow state is persisted durably before the HITL notification is sent (write-before-notify).
- HITL state survives platform restarts.
- Human decisions are received through the platform's HITL resolution interface and recorded as workflow events in the audit log.
- The Orchestration Agent resumes the workflow upon receipt of a valid resolution signal.
- A HITL escalation that reaches its configured timeout with no response triggers a platform alert to the agent owner. It does not default to any autonomous action.

---

## 9. Agent Lifecycle

### 9.1 Deployment

A new agent instance MUST satisfy all of the following before it is deployed to any environment where it processes real alert data:

- [ ] Agent definition file complete (role, owner, policy reference, model configuration)
- [ ] Policy file reviewed and merged per `docs/ENGINEERING.md` §3 (Stage 3–4)
- [ ] Evaluation suite passes all per-role thresholds defined in this document
- [ ] Security review completed if the agent's capability set includes any tool in a sensitive code area (`docs/SECURITY.md` §5)
- [ ] Owner has acknowledged accountability in writing (comment in the deployment PR)

### 9.2 Versioning

Agent versions follow the platform's semantic versioning semantics (`docs/ENGINEERING.md` §11.1) with one addition:

- A change to an agent's **policy** (capability set, thresholds, prohibited actions) is always a minor version bump, regardless of the implementation change scope.
- A change to an agent's **output schema** that breaks downstream consumers is a major version bump.
- The version is recorded in every reasoning trace (`model_id` and `agent_version` fields).

Two versions of the same agent role MAY run simultaneously during a staged rollout, provided they share the same session schema version. Incompatible session schema versions require a migration plan before dual-run.

### 9.3 Retirement

An agent version is retired when it is superseded by a new version. Retirement MUST follow this sequence:

1. New version passes all evaluation thresholds and is deployed.
2. All in-flight workflows using the old version are allowed to complete or are migrated (no forced termination).
3. All active HITL escalations tied to the old version are resolved or transferred to the new version.
4. Retirement is recorded in the agent's definition file and the audit log.

An agent version MUST NOT be hard-deleted while any investigation artifact, reasoning trace, or audit log entry references it. The definition file is retained in version control indefinitely.

---

*Amendments to this document that change capability sets (§§3.2, 4.2, 5.2, 6.2), authorization gate conditions (§6.4), or per-role evaluation thresholds (§§3.5, 4.5, 5.5, 6.6) require maintainer council review. These are load-bearing security decisions.*
