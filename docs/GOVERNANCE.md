# Project Governance — Sentinel AI

This document establishes the governance model, decision-making structure, and security disclosure policy for Sentinel AI.

---

## 1. Governance Philosophy

Sentinel AI is an open-source security response platform. Because security platforms handle high-trust operations, open governance, transparent auditability, and clear maintainer accountability are fundamental.

---

## 2. Roles and Responsibilities

- **Contributors**: Anyone who submits issues, pull requests, documentation updates, or feedback.
- **Maintainers**: Core members responsible for architectural integrity, review sign-offs, security audits, and release management.

---

## 3. Decision-Making Process (ADR Lifecycle)

- Any architectural change, data schema update, or boundary modification **MUST** be proposed via an Architecture Decision Record (ADR) in `.ai/decisions/`.
- Merging an ADR requires review sign-off from at least **2 core maintainers**.

---

## 4. Security Vulnerability Reporting

If you discover a security vulnerability in Sentinel AI, please do **NOT** open a public issue.
- Email: `security@sentinel-ai.org`
- GPG Key: Available in `SECURITY.md`
- Response SLA: Acknowledgment within 24 hours; patch proposal within 72 hours.
