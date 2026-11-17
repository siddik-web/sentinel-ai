# Local Development Setup — Sentinel AI

This document is the authoritative reference for setting up the local development environment for Sentinel AI.

---

## Prerequisites

- **Python**: 3.11 or higher
- **Package Manager**: `pip` (or `uv`)
- **Git**: 2.30+
- **Docker** (optional): for the reference deployment

---

## Initial Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/siddik-web/sentinel-ai.git
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

## Running the Platform

- **Start the server and web console** (http://127.0.0.1:8000):
  ```bash
  sentinel-ai serve
  ```

- **Run with Docker Compose**:
  ```bash
  docker compose up --build
  ```

Configuration variables, the HTTP API, and the CLI are documented in the [README](../README.md).

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
  ruff check .
  ```

- **Run the Behavioral Evaluation Corpus**:
  ```bash
  sentinel-ai evaluate tests/fixtures/alert_corpus
  ```

The same checks run in CI (`.github/workflows/ci.yml`) on every pull request.
