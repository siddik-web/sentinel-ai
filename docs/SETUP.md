# Local Development Setup — Sentinel AI

This document is the authoritative reference for setting up the local development environment for Sentinel AI.

---

## Prerequisites

- **Python**: 3.11 or higher
- **Package Manager**: `pip` (or `uv`)
- **Git**: 2.30+

---

## Initial Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/sentinel-ai/sentinel-ai.git
   cd sentinel-ai
   ```

2. **Create and Activate Virtual Environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

---

## Running Tests and Linting

- **Run Unit & Integration Tests**:
  ```bash
  pytest
  ```

- **Run Coverage Check**:
  ```bash
  pytest --cov=sentinel_ai --cov-report=term-missing tests/
  ```

- **Lint Codebase**:
  ```bash
  ruff check src/ tests/
  ```
