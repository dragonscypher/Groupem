# Contributing to Groupem

## Development Environment
1. Clone repo and install dependencies:
```powershell
npm install
```
2. Generate Prisma client:
```powershell
cd mcp-server
npx prisma generate
cd ..
```
3. Copy `.env.example` to `.env` and adjust.
4. (Optional) Start ML service:
```powershell
cd ml-service
python -m venv .venv
. .venv/Scripts/Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --port 8000
```
5. Run server + ML concurrently:
```powershell
npm run dev
```
6. Build extension:
```powershell
npm -w extension run build
```

## Scripts Overview
- `npm run dev:mcp` – MCP server (ts-node-dev)
- `npm run dev:ml` – FastAPI ML service
- `npm run dev` – Concurrent server + ML
- `npm run build` – Build shared libs, server, extension
- `npm test` – Unit/integration tests
- `npm run test:e2e` – Playwright tests

## Code Style
- TypeScript strictness maintained; avoid unnecessary any.
- Keep functions small and purposeful.
- Do not commit generated `dist/` except for packaged extension release branches.

## Security & Secrets
- Never commit real secrets. `.env` is ignored.
- Rotate `JWT_SECRET` for production deployments.

## Pull Requests
- Include description & rationale.
- Ensure `npm test` passes locally.
- Run `npm -w shared run build` if modifying shared models.

## Commit Messages
Follow conventional style (recommended):
- `feat: add X`
- `fix: correct Y`
- `docs: update README`
- `refactor: simplify Z`

## Testing Guidance
- Add unit tests for new utilities.
- Extend Playwright E2E if UI flows change.

## Issue Reporting
Include reproduction steps, expected vs actual behavior, and environment (OS, Node, Python versions).

Happy hacking!
