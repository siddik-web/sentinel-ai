# Engineering Standards — Sentinel AI

> **Document class:** Engineering handbook
> **Status:** Active
> **Scope:** All code contributions to the Sentinel AI platform
> **Derived from:** `PROJECT_CHARTER.md` §10 (EP1–EP8)

---

## Table of Contents

1. [Purpose and Scope](#1-purpose-and-scope)
2. [Who This Document Is For](#2-who-this-document-is-for)
3. [Engineering Lifecycle](#3-engineering-lifecycle)
4. [Development Environment](#4-development-environment)
5. [Branching and Version Control](#5-branching-and-version-control)
6. [Code Standards](#6-code-standards)
7. [Testing Standards](#7-testing-standards)
8. [Quality Gates](#8-quality-gates)
9. [Security Engineering Practices](#9-security-engineering-practices)
10. [AI-Assisted Development](#10-ai-assisted-development)
11. [Versioning and Release](#11-versioning-and-release)
12. [Definition of Done](#12-definition-of-done)
13. [Engineering Debt](#13-engineering-debt)

---

## 1. Purpose and Scope

This document translates the engineering principles in `PROJECT_CHARTER.md` §10 (EP1–EP8) into actionable practice. It defines how work moves from an open issue to a merged commit, what standards code must meet, and what "done" means for any contribution to Sentinel AI.

**This document governs:** engineering lifecycle, development environment, version control conventions, code standards, testing requirements, quality gates, security engineering practices at the code level, AI-assisted development, versioning semantics, definition of done, and engineering debt policy.

**This document does not govern:** system architecture decisions (`architecture/ARCHITECTURE.md`), agent interface specifications (`agents/AGENTS.md`), evaluation methodology (`.ai/AI_PRINCIPLES.md`), platform threat model and security controls (`docs/SECURITY.md`), or open source governance (`docs/GOVERNANCE.md`). When a topic is not listed in scope above, the authoritative document is the one in parentheses.

---

## 2. Who This Document Is For

| Reader | Sections most relevant |
|---|---|
| External contributor (first contribution) | §3, §4, §5, §6, §12 |
| Core maintainer | All sections |
| AI/ML engineer | §3, §7.4, §8.3, §10 |
| Security engineer | §3 Stage 6, §8.2, §9 |
| Release manager | §11, §12 |

New contributors SHOULD read §3 (Engineering Lifecycle) and §12 (Definition of Done) before opening a pull request.

---

## 3. Engineering Lifecycle

Every contribution MUST follow the stages below in order. Each stage defines an entry condition, the work required, and the exit condition. The **Skip if** clause defines when a stage is not required — it is not a discretionary opt-out.

### Stage 0 — Issue Creation

**Entry:** Any idea, bug report, or task.
**Work:** Open a GitHub Issue using the project template. Issues classified as `new-component`, `architecture-change`, or `security-relevant` MUST include: Objective, Why it matters, Dependencies, and Acceptance Criteria. Issues without these fields MUST NOT be moved to `in-progress`.
**Exit:** Issue triaged, labeled, and milestone-assigned by a maintainer.

### Stage 1 — Specification

**Entry:** Issue classified as `new-component`, `architecture-change`, or `security-relevant`.
**Work:** Author a design spec in `specs/` defining the component's interface contract, failure modes, and test strategy. The spec MUST be reviewed and merged before implementation begins. Implementation that precedes a merged spec is a process violation.
**Exit:** Spec PR merged and issue unblocked for implementation.
**Skip if:** Bug fix, documentation change, dependency update, or minor feature with no new interface.

### Stage 2 — Architecture Review

**Entry:** Spec introduces a cross-cutting concern: data model change, public API addition, audit log format change, policy language extension, or agent interface change.
**Work:** A maintainer reviews the spec against `architecture/ARCHITECTURE.md` and all ratified ADRs. Conflicts MUST be resolved before implementation proceeds.
**Exit:** Reviewer sign-off recorded in the spec PR.
**Skip if:** Spec is self-contained and introduces no new cross-cutting interfaces.

### Stage 3 — ADR

**Entry:** Architecture review surfaces a decision with meaningful alternatives and non-obvious tradeoffs.
**Work:** Author an ADR in `.ai/decisions/` covering: context, options considered, decision made, and consequences. The ADR MUST be merged before implementation begins.
**Exit:** ADR merged.
**Skip if:** Only one sensible option exists — document rationale in the commit message instead.

### Stage 4 — Implementation

**Entry:** Spec approved; ADR merged if one was required.
**Work:** Implement against the spec. One PR per logical change. If implementation reveals the spec was incorrect, the spec MUST be updated first. Silent divergence from the spec is not permitted.
**Exit:** All quality gates pass (§8).

### Stage 5 — Testing

**Entry:** Implementation complete on a feature branch.
**Work:** Author tests at the applicable levels defined in §7. For changes to agent logic, run the behavioral evaluation suite. For changes to sensitive code areas (§9.3), run the security test suite.
**Exit:** Coverage thresholds met; behavioral benchmarks pass, or a regression is documented and explicitly accepted by a maintainer.

### Stage 6 — Security Review

**Entry:** Change touches a sensitive code area (§9.3).
**Work:** A reviewer other than the implementer, with a security background, reviews the diff for: injection vectors, privilege escalation paths, audit log bypass conditions, and state machine violations.
**Exit:** Security reviewer records written sign-off in the PR.
**Skip if:** Change does not touch any area listed in §9.3.

### Stage 7 — Code Review

**Entry:** All applicable tests pass; security review complete if required.
**Work:** Peer review against the spec, conventions (§6), and engineering principles (charter EP1–EP8). The reviewer confirms: the change does what the spec describes, failure modes are handled, and the change is self-contained.
**Exit:** Required approvals obtained. **2 approvals** for core runtime, policy engine, and audit log. **1 approval** for integrations, documentation, tooling, and tests.

### Stage 8 — Merge

**Entry:** All gates passed; all required approvals obtained.
**Work:** Squash or rebase-merge per the project's merge strategy. The commit message MUST reference the issue number and, where applicable, the ADR number.
**Exit:** Feature branch deleted; issue closed.

### Stage 9 — Release

**Entry:** Milestone complete — all issues closed or explicitly deferred with written rationale.
**Work:** Follow the release checklist in §11.2. Changelog updated. Tag pushed. GitHub Release published.
**Exit:** Milestone closed.

---

## 4. Development Environment

### 4.1 Prerequisites

The project MUST maintain a `docs/SETUP.md` listing all required tools and their minimum versions. That file is authoritative for toolchain versions. This section defines policy only.

All contributors MUST be able to reach a fully passing test suite from a clean checkout using only the steps in `docs/SETUP.md`. If those steps fail in CI, the documentation is the defect — not CI.

### 4.2 Local Setup

The setup procedure MUST be reproducible via a documented command sequence and MUST be validated in CI on every change to `docs/SETUP.md`. A contributor SHOULD be able to run all non-behavioral tests without live external API credentials.

### 4.3 Dependency Management

All direct and transitive dependencies MUST be pinned to exact versions with verified checksums in a lockfile committed to the repository. PRs that modify the lockfile MUST include an explanation of what changed and why. Unpinned dependencies in production code are a blocking CI finding.

---

## 5. Branching and Version Control

### 5.1 Branch Naming

Branches MUST follow the pattern: `<type>/issue-<number>-<short-description>`.

Valid types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `security`.

Example: `feat/issue-7-agents-md`, `security/issue-31-policy-input-validation`.

### 5.2 Commit Standards

Commits MUST follow the [Conventional Commits](https://www.conventionalcommits.org/) specification. The subject line MUST be 72 characters or fewer. The body SHOULD explain *why* the change was made — the diff communicates *what*. Issue and ADR references MUST appear in the commit footer.

Force-pushing to `main` or any release branch is PROHIBITED. History rewriting after a branch has been pushed for review is PROHIBITED.

### 5.3 PR Discipline

A PR MUST represent a single logical change. A PR that combines a refactor with a feature addition MUST be split before review begins. The PR description MUST reference the linked issue, the merged spec (if applicable), and any ADRs created or consulted during the lifecycle.

---

## 6. Code Standards

### 6.1 Style and Formatting

Formatting MUST be enforced by an automated tool configured in the repository root. Formatting violations are a CI gate failure. Formatting disputes are resolved by the tool configuration — not by review discussion.

### 6.2 Language-Specific Conventions

Naming conventions, module structure, type annotation requirements, and import ordering are defined in `docs/CONVENTIONS.md`. That file is authoritative; this section does not duplicate it.

### 6.3 Documentation in Code

Inline comments MUST explain *why*: a non-obvious constraint, a deliberate invariant, a workaround for a known external behavior. Comments that describe *what* the code does are redundant and SHOULD be removed. Public interfaces MUST carry documentation covering: parameters, return values, failure modes, and any side effects. Docstrings on internal implementation are optional.

---

## 7. Testing Standards

### 7.1 Test Taxonomy

Sentinel AI uses four test levels with distinct scopes and dependency constraints:

| Level | Scope | Live dependencies | Assertion target |
|---|---|---|---|
| Unit | Single function or class | None | Exact outputs, error conditions |
| Integration | Multiple components via their interfaces | Test doubles only | Interface contracts, data flows |
| Behavioral | Agent + policy engine end-to-end | Model API optional (recorded responses acceptable) | Output correctness within defined thresholds |
| Security | Security-sensitive components (§9.3) | None | Absence of defined vulnerability classes |

### 7.2 Unit Testing

Unit tests MUST be co-located with the code under test. A unit test MUST NOT make network calls, write to disk outside a temporary directory, or depend on execution order. Mocking external dependencies is required; mocking internal dependencies is permitted when it reduces brittleness without hiding a real integration concern.

### 7.3 Integration Testing

Integration tests MUST use test doubles for all external dependencies — model provider APIs, SIEM integrations, and response targets. A test that requires a live external service is an end-to-end test, not an integration test, and MUST be categorized and gated accordingly.

### 7.4 Behavioral Testing

> **⚠ Stub — Blocked on `agents/AGENTS.md` (Issue #7)**
>
> Complete behavioral testing standards require the agent role taxonomy and interface contracts defined in `agents/AGENTS.md`. This section MUST be completed and this stub removed before the v0.1 release.
>
> **Interim requirements until this section is finalized:**
> - Any change to agent prompts, reasoning chains, tool definitions, or model interface configuration MUST include at least one end-to-end test against a recorded alert fixture from the project's fixture corpus.
> - Behavioral regressions are treated as blocking findings, not flaky tests.
> - The accuracy threshold from `PROJECT_CHARTER.md` §13 Exit Criterion 6 (≥85% on the representative alert corpus) applies to all agent changes until a more specific threshold is ratified in this section.
> - A maintainer MUST review and record the behavioral test result in the PR before merge.

### 7.5 Security Testing

Security tests MUST cover the vulnerability classes defined in `docs/SECURITY.md`. At minimum, every security test suite targeting a sensitive code area (§9.3) MUST include: input validation boundary cases, policy engine deny-path coverage, and audit log completeness under error and exception conditions. Security tests MUST NOT require credentials or a live environment to execute.

### 7.6 Coverage Thresholds

Coverage thresholds are defined per module in the CI configuration and enforced as a gate. The default minimum is **80% line coverage** for new code. Modules listed in §9.3 (sensitive code areas) carry a minimum of **90%**. Threshold reductions require written maintainer sign-off committed to the repository. PRs that introduce a coverage regression without a matching sign-off MUST NOT be merged.

---

## 8. Quality Gates

### 8.1 Pre-Merge Gates (CI)

The following MUST pass on every PR targeting `main`. They are enforced automatically and MUST NOT be bypassed.

- [ ] All applicable test levels pass with no failures
- [ ] Coverage thresholds met for all changed modules (§7.6)
- [ ] SAST scan produces no new findings at or above the configured severity threshold
- [ ] Dependency vulnerability scan produces no new critical or high CVEs
- [ ] Commit messages conform to the Conventional Commits standard (§5.2)
- [ ] Lockfile is consistent with dependency declarations (§4.3)

CI skip flags (`[skip ci]`, `[no ci]`) are PROHIBITED on PRs targeting `main`.

### 8.2 Security-Sensitive Component Gates

Changes to any area listed in §9.3 require Stage 6 (Security Review) in addition to all CI gates. This gate:

- MUST be performed by a reviewer other than the implementer
- MUST produce written sign-off recorded in the PR
- CANNOT be satisfied by automated tooling alone
- Blocks merge until sign-off is present — no exceptions

### 8.3 Agent Behavioral Gates

> **⚠ Stub — Blocked on `agents/AGENTS.md` (Issue #7) and `.ai/AI_PRINCIPLES.md` (Issue #6)**
>
> Automated behavioral gate thresholds and tooling depend on the evaluation framework defined in `.ai/AI_PRINCIPLES.md` and the agent taxonomy in `agents/AGENTS.md`. This section MUST be completed before v0.1 ships.
>
> **Interim gate:** Any change to agent prompts, reasoning chains, tool definitions, or model interface configuration MUST include a maintainer-reviewed behavioral test result comment in the PR. The comment MUST document: the fixture set used, the accuracy result, and a comparison to the prior run. A regression with no documented acceptance by a maintainer is a blocking finding.

---

## 9. Security Engineering Practices

### 9.1 Threat Modeling in the Lifecycle

Any Stage 1 spec for a change to a sensitive code area (§9.3) MUST include a threat model using the STRIDE framework as a minimum. The threat model is authored in the spec document and linked from any ADR created for the change. It is not a separate deliverable — it is part of the spec.

The platform-level threat model is owned by `docs/SECURITY.md`. ENGINEERING.md defines *when* threat modeling is invoked; SECURITY.md defines *what* the threat model covers.

### 9.2 Dependency Security

Dependencies MUST be scanned for known vulnerabilities on every CI run and on a weekly automated schedule. A new critical or high CVE in a direct dependency is a blocking finding. A patch or documented exception MUST be produced within 14 days, consistent with `PROJECT_CHARTER.md` §12 Security Metrics.

Exceptions MUST be: written, time-bounded (maximum 30 days), and approved by a maintainer. Exception files are committed to the repository under `docs/security-exceptions/`. Silent acceptance of CVEs — no scan result acknowledged, no exception filed — is PROHIBITED.

### 9.3 Sensitive Code Areas

The following components require Stage 6 (Security Review) for any change. This list is the authoritative source; CI tooling references it.

- **Policy engine** — evaluation logic, policy parser, policy file loader
- **Audit log** — write path, format serialization, integrity chain
- **Authentication and authorization layer**
- **Agent tool execution interface**
- **HITL state machine and escalation path**
- **External integration adapters** — inbound event parsing and outbound action dispatch

Adding a component to this list requires maintainer sign-off. Removing a component requires an ADR.

---

## 10. AI-Assisted Development

AI coding assistants are in active use by contributors. The same governance principle applied to production agents applies here: govern before you automate (charter PP2). Policy governs review standard and prohibited areas — not tooling choice.

### 10.1 Permitted Uses

Contributors MAY use AI assistants for: generating boilerplate and scaffolding, drafting documentation and specs, suggesting test cases, explaining unfamiliar code, and proposing refactors. These uses are encouraged where they accelerate delivery of correct, reviewable output.

### 10.2 Prohibited Uses

AI assistants MUST NOT be:

- The sole author of security-relevant logic in a sensitive code area (§9.3) — the human contributor MUST author and be able to explain the security-critical portions
- Used as a substitute for a required human reviewer at any stage
- Given access to production credentials, live security event data, real alert payloads, or any production system

### 10.3 Review Standard for AI-Generated Code

AI-generated code is reviewed to the same standard as human-generated code. A reviewer who applies lighter scrutiny because a section was AI-generated is in violation of this standard. The contributor submitting the PR is accountable for all code in it, regardless of origin.

---

## 11. Versioning and Release

### 11.1 Versioning Semantics

Sentinel AI uses [Semantic Versioning](https://semver.org/). Definitions specific to this project:

| Increment | Meaning | Upgrade safety |
|---|---|---|
| Patch (0.0.x) | Bug fix, no interface change | Safe; no testing required |
| Minor (0.x.0) | New capability, backward-compatible change | **Pre-v1.0:** MAY include breaking changes; adopters accept this risk. From v1.0: backward-compatible only. |
| Major (x.0.0) | Breaking change to a public interface | From v1.0: MUST follow deprecation policy (§11.3). Pre-v1.0: not applicable. |

Pre-v1.0 minor version releases that include breaking changes MUST document them explicitly in the release notes. "Breaking change" means: a public interface is removed, renamed, or changes behavior in a way that requires adopter code changes.

### 11.2 Release Checklist

A release MUST NOT be tagged until all of the following are verified:

- [ ] All milestone issues are closed or explicitly deferred with written rationale
- [ ] All CI gates pass on the release commit
- [ ] CHANGELOG.md is updated with entries for all changes since the prior release
- [ ] Security dependency scan completed on the release commit with no open critical or high findings
- [ ] Release notes reviewed and approved by at least one maintainer other than the release author
- [ ] `docs/SETUP.md` reflects the current toolchain requirements

### 11.3 Deprecation Policy

From v1.0 onward, a public interface or documented behavior MUST NOT be removed without: a deprecation notice in the prior minor release, documented migration guidance, and a CHANGELOG entry. Pre-v1.0, deprecations SHOULD follow this process but are not required to.

### 11.4 Changelog Standards

Each CHANGELOG entry MUST include: what changed, which issue it closes, and — for breaking changes — the exact migration steps. Entries written as "various improvements," "bug fixes," or "internal refactoring" without specifics are not acceptable and will be returned for revision.

---

## 12. Definition of Done

A contribution is complete when every item below is true. This checklist is binary — an item is either verifiably met or it is not. Partial completion is not done.

- [ ] All acceptance criteria in the linked issue are verifiably satisfied
- [ ] Tests written at all applicable levels (§7) and passing in CI
- [ ] Coverage thresholds met for all changed modules (§7.6)
- [ ] Security review completed and sign-off recorded if the change touches a sensitive code area (§9.3)
- [ ] Behavioral evaluation results documented in the PR if the change touches agent logic (§8.3)
- [ ] Inline documentation updated for any changed public interface
- [ ] Spec updated if implementation diverged from the original spec
- [ ] CHANGELOG.md updated with an entry for this change
- [ ] Failure modes documented for any new component (charter EP8)
- [ ] ADR written and merged if an architectural decision was made (Stage 3)
- [ ] No TODOs or FIXMEs introduced — if deferral is intentional, a tracking issue MUST be opened and its number referenced in the code comment
- [ ] PR description references: the issue number, the spec (if applicable), and any ADRs consulted

---

## 13. Engineering Debt

### Definition

Engineering debt is any intentional shortcut or documented deficiency accepted in exchange for short-term delivery. It is distinct from undiscovered defects. Undiscovered defects are bugs; they are not debt.

### Acceptance Policy

New intentional debt MAY be accepted only with three things present: a written justification, a classification (see below), and a resolution milestone assigned by a maintainer. Debt incurred without documentation is a process violation and is treated the same as any other undocumented defect.

### Classification

| Class | Definition | Treatment |
|---|---|---|
| **Security debt** | Known weakness in a sensitive code area (§9.3) | Not backlog. Treated as a defect. MUST have a resolution milestone within the current or next minor release. |
| **Architectural debt** | Deviation from `architecture/ARCHITECTURE.md` or a ratified ADR | Requires a new ADR documenting the deviation and the resolution plan before the deviation is accepted. |
| **Operational debt** | Missing observability, deployment hardening, or runbook gaps | Backlog. MUST be resolved before v1.0. |
| **Quality debt** | Coverage below threshold, missing tests, or incomplete documentation | Backlog. MUST be resolved before the affected component is marked production-ready. |

Security debt that reaches its resolution milestone without being resolved MUST be escalated to the maintainer council. It MUST NOT be silently deferred to the following milestone.

---

*Amendments to this document follow the process defined in `PROJECT_CHARTER.md` Amendment Process. Changes to §8 (Quality Gates), §9.3 (Sensitive Code Areas), or §12 (Definition of Done) require maintainer council review before merging.*
