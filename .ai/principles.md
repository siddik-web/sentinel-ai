# Sentinel AI — Principles

Principles are the working guidance that turns the [constitution](constitution.md) into
day-to-day practice. The constitution says _what must always hold_; principles say
_how we get there_. They can evolve more freely than the constitution.

## Engineering Principles

- **Small, reversible changes.** Prefer the smallest change that fully solves the problem.
- **Read before you write.** Understand the surrounding code and match its conventions.
- **Verify, don't assume.** Run it, test it, observe it before claiming it works.
- **Make the implicit explicit.** Surface assumptions and trade-offs in writing.

## Collaboration Principles

- **One source of truth.** Specs live in `specs/`, architecture in `architecture/`,
  decisions in `.ai/decisions/`.
- **Reusable prompts and workflows.** Capture repeatable agent work in `.ai/prompts/`
  and `.ai/workflows/` instead of re-deriving it each time.

## Decision-Making

- Significant choices get an entry in `.ai/decisions/` (an ADR-style record).
- When principles conflict, defer to the [constitution](constitution.md).
