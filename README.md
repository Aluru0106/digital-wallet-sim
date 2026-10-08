# PayLite – Digital Wallet & Payment Gateway Simulator

Secure Software Engineering (24CYS401) end-semester lab – problem statement 18.

**Features:** user registration · wallet creation · simulated top-up · merchant registration ·
payment initiation → confirmation · refund · transaction history · admin audit log.

**Integrity & security:** HMAC request signing (tampering) · timestamp + single-use nonce (replay) ·
Idempotency-Key (duplicate charges) · `BEGIN IMMEDIATE` + conditional updates (double spending / race
conditions) · JWT + bcrypt + lockout (authentication) · role & ownership checks (authorization) ·
hash-chained append-only audit log.

## Run locally (Python)
```bash
pip install -r requirements-dev.txt
pytest                      # unit + integration + fuzz
uvicorn app.main:app --reload   # http://127.0.0.1:8000
```

## Run with Docker
```bash
docker build -t paylite:local .
docker run --rm -p 8000:8000 --read-only --tmpfs /data:uid=10001,gid=10001 --tmpfs /tmp --cap-drop ALL \
  -e JWT_SECRET=$(openssl rand -base64 48) -e HMAC_SECRET=$(openssl rand -base64 48) \
  -e ADMIN_USERNAME=admin -e ADMIN_PASSWORD='Choose-A-Strong-One' paylite:local
```
Open http://localhost:8000 (must be `localhost` – the browser's WebCrypto needs a secure context).

## Kubernetes (Minikube)
```bash
minikube start && minikube image load paylite:local   # or build inside minikube
kubectl apply -f k8s/00-namespace.yaml
kubectl -n paylite create secret generic paylite-secrets --from-literal=JWT_SECRET=$(openssl rand -base64 48) \
  --from-literal=HMAC_SECRET=$(openssl rand -base64 48) --from-literal=ADMIN_USERNAME=admin --from-literal=ADMIN_PASSWORD='Choose-A-Strong-One'
sed -i 's/paylite:ci/paylite:local/' k8s/20-deployment.yaml
kubectl apply -f k8s/20-deployment.yaml -f k8s/30-service.yaml -f k8s/40-networkpolicy.yaml
kubectl -n paylite port-forward svc/paylite 8080:80
BASE_URL=http://127.0.0.1:8080 pytest tests/system -v
```

## CI/CD
`.github/workflows/ci-cd.yml`: checkout → install → gitleaks → Bandit → pip-audit → pytest (+coverage) →
SonarCloud → Docker build → Trivy → container smoke test → push to GHCR → Minikube deploy → system tests.

`legacy/wallet_v1.py` is the deliberately insecure first version kept as *before* evidence; it is never deployed.
