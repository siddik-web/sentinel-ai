# Code Conventions — Sentinel AI

This document establishes the Python coding conventions and standards for Sentinel AI.

---

## 1. Naming Conventions

- **Modules & Packages**: `snake_case` (e.g., `sentinel_ai/core/ocsf`)
- **Classes**: `PascalCase` (e.g., `BaseEvent`, `DataSourceAdapter`)
- **Functions & Methods**: `snake_case` (e.g., `validate_event`, `append_log`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `OCSF_SCHEMA_VERSION`)

---

## 2. Type Annotations

- All public functions, methods, and class attributes **MUST** include explicit Python type hints.
- Use `Pydantic v2` for structured runtime data validation and serialization.

---

## 3. Error Handling

- Raise domain-specific exceptions inheriting from `SentinelError`.
- Never catch generic `Exception` silently without logging or re-raising.
- Input validation failures MUST reject data at the ingress boundary before hitting internal components.
