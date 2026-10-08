# Security controls (secure build checklist)

| # | Control | Where |
|---|---------|-------|
| 1 | Least privilege - workflow `permissions: contents: read`, only the container job gets `packages: write`; pod runs as UID 10001 with all capabilities dropped | `.github/workflows/ci-cd.yml`, `Dockerfile`, `k8s/20-deployment.yaml` |
| 2 | Secret management - no secrets in code; env vars from GitHub Secrets / Kubernetes Secret; app refuses to start in prod without them; gitleaks scan on every push | `app/config.py`, `.env.example`, `k8s/10-secret.example.yaml` |
| 3 | Dependency control - exact version pins, `pip-audit` gate, Dependabot weekly updates | `requirements*.txt`, `.github/dependabot.yml` |
| 4 | Code review - CODEOWNERS + pull request required on `main` | `.github/CODEOWNERS`, branch protection |
| 5 | Protected branches - `main`: PR required, 1 approval, status checks must pass, no force-push | GitHub → Settings → Branches |
| 6 | Reproducible builds - pinned base image tag, pinned deps, multi-stage Dockerfile, `.dockerignore` | `Dockerfile` |
| 7 | Artifact integrity - image tagged with commit SHA and pushed to GHCR; digest recorded | `container` job |
| 8 | Automated static/security checks - Bandit (SAST), SonarCloud, Trivy (image), pip-audit (SCA), gitleaks (secrets) | `build-test` / `container` jobs |

Report a vulnerability: open a private security advisory on this repository.
