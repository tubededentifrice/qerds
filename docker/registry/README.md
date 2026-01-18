# Internal OCI registry (dev / security tooling)

This repository optionally runs a minimal, self-hosted OCI registry for **security tooling** (e.g., mirroring Trivy DB artifacts for offline scanning).

## Start

1. Create a local `.env` (see `.env.example`) and set `QERDS_REGISTRY_USER` / `QERDS_REGISTRY_PASSWORD`.
2. Start the profile:

```bash
docker compose --profile security-tools up -d registry
```

The registry is available **inside** the compose network at `http://registry:5000` and is protected by **basic auth** (htpasswd).

## Notes

- No host port is published by default (reduces exposure on the developer machine).
- This is **not** a production hardening guide; production deployments typically require TLS, network segmentation, and registry governance.

