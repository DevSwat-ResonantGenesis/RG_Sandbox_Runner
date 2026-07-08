# RG Sandbox Runner

> **Part of the [ResonantGenesis](https://dev-swat.com) platform** — Isolated sandbox execution service for agent code runs.

[![Status: Production](https://img.shields.io/badge/Status-Production-brightgreen.svg)]()
[![Port: 9001](https://img.shields.io/badge/Port-9001-orange.svg)]()
[![License: RG Source Available](https://img.shields.io/badge/License-RG%20Source%20Available-blue.svg)](LICENSE.txt)

Provides sandboxed code execution environments via Docker containers. Used by `agent_engine_service` for per-run agent sandbox isolation. Supports HTTP GET proxying with SSRF protection, IP validation, and resource limits.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `DOCKER_SOCKET` | Docker socket path (default: `/var/run/docker.sock`) |

## Quick Start

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 9001 --reload
```

## Deployment Status

- **Extracted from**: `genesis2026_production_backend/sandbox_runner_service/`
- **Server path**: `/home/deploy/RG_Sandbox_Runner`
- **Docker service**: `sandbox_runner_service`
- **Volume mounts**: `/var/run/docker.sock` (Docker-in-Docker)

---
**Organization**: [DevSwat-ResonantGenesis](https://github.com/DevSwat-ResonantGenesis) | **Platform**: [dev-swat.com](https://dev-swat.com)
