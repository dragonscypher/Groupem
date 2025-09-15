# Groupem

Cross-browser tab grouping extension with secure MCP server and optional ML microservice.

## Components
- Extension (Chrome/Firefox) in `extension/`
- MCP Server (Node/TypeScript + Prisma + SQLite) in `mcp-server/`
- ML Service (FastAPI) in `ml-service/`
- Shared models in `shared/`

## Quick Start (PowerShell)
```powershell
# Install root deps
npm install

# Generate Prisma client
setx DATABASE_URL "file:./dev.db"
cd mcp-server; npx prisma generate; cd ..

# Run server (port 8080 default; will auto-increment if busy)
# Optionally set explicit port
$env:PORT=8080; npm run dev:mcp

# Run extension build (dev)
cd extension; npm run dev
```

## ML Service
```powershell
cd ml-service
python -m venv .venv
. .venv/Scripts/Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

### Health
MCP server exposes `GET /ml/health` reflecting reachability of `ML_URL` (default `http://localhost:8000`).
Set a custom ML URL:
```powershell
$env:ML_URL="http://localhost:9000"; npm run dev:mcp
```
If unreachable, embeddings in extension fall back to:
1. (Future) Local ONNX model (placeholder)
2. Server-side TF-IDF stub
Check server logs for: `ML service unreachable at ...`.

### Ports
Server attempts desired `$env:PORT` (default 8080) then increments up to 10 times if occupied.
Use `/` root route for basic health and `/ml/health` for ML status.

## Environment Variables
See `.env.example` for documented defaults:
- `PORT` – MCP server port (auto-increment fallback)
- `JWT_SECRET` – Signing key (change for production)
- `DATABASE_URL` – Prisma SQLite path
- `ML_URL` – Base URL for ML microservice

## CI
GitHub Actions workflow (`.github/workflows/ci.yml`) installs dependencies, builds all packages, runs tests, and executes a Chromium Playwright project (soft-fail for E2E).

## Contributing
See `CONTRIBUTING.md` for guidelines, scripts, and commit style.

## Release Checklist
- Update version numbers (extension + server) if public release.
- Run `npm run build` and `npm test`.
- Tag release: `git tag -a vX.Y.Z -m "Release vX.Y.Z"; git push --tags`.
- Upload packaged extension (zip `extension/dist`).
```

## Tests
```powershell
# (After installing deps) build shared & server
npm -w shared run build
npm -w mcp-server run build
npm test
```

## Security Notes
- Argon2id used for password hashing.
- AES-GCM encryption of sessions and storage with per-user random key unwrapped at login (kept in-memory only).
- TOTP enrollment and verification endpoints provided.
- Simplified WebAuthn (mock) endpoints included; not production secure.
- Registration now supports optional `phone` and automatic TOTP secret provisioning (returned in `totpSecret`). Store it in an authenticator app to use during login.

## Embeddings
Current implementation uses a simple TF-IDF style embedding in the server; ML service provides higher quality embeddings & clustering if integrated via future enhancement.

## Disclaimer
This repository is a functional baseline but additional hardening, full WebAuthn ceremony, and production deployment considerations (HTTPS, key management) are required before production use.
