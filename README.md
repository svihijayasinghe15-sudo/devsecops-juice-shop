# devsecops-juice-shop

A DevSecOps pipeline built around OWASP Juice Shop (Node.js / Angular).
**Module:** IE3142 DevOps Security, SLIIT.

## Requirements

* Docker
* Docker Compose
* Git

## Run the app

1. Clone the repo:

```bash
git clone https://github.com/svihijayasinghe15-sudo/devsecops-juice-shop.git
cd devsecops-juice-shop
```

2. Start the app with one command:

```bash
docker compose up -d
```

3. Open in your browser:

```text
http://localhost:3000
```

## Stop the app

```bash
docker compose down
```

## Repo contents

* `docker-compose.yml` — starts Juice Shop
* `.github/workflows/` — CI/CD pipeline with 4 security gates:

  * SAST
  * Dependency scan
  * Secrets scan
  * Trivy image scan
* `ThreatDragonModels/` — STRIDE threat model
* `semgrep-*.txt` — SAST scan reports (before/after fixes)

## Security note

Juice Shop is intentionally vulnerable. Run it only on your own laptop.

**Do not expose it to the internet.**

No secrets are stored in this repo. Pipeline secrets use GitHub Actions secrets.
