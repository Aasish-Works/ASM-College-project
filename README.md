# Enterprise Attack Surface Management (ASM) Platform

Enterprise-grade ASM platform for authorized security testing and defense research. This build includes:

- EPSS enrichment plus contextual enterprise risk scoring for CVE-backed findings.
- Multi-source intelligence, graph correlation, attack-path modeling, and target drill-down views.
- Scan orchestration with job queue, retry/backoff, prioritization, projected stages, and scanner-node heartbeat.
- Tool execution pipeline for `subfinder`, `amass`, `assetfinder`, `puredns`, `dnsx`, `naabu`, `masscan`, `nmap`, `httpx`, `tlsx`, `whatweb`, `xingfinger`, `wafw00f`, `gau`, `waybackurls`, `waymore`, `katana`, `hakrawler`, `ffuf`, `dirsearch`, `nuclei`, `kxss`, `dalfox`, `nikto`, and `playwright`.
- Vulnerability lifecycle operations: assignment, ticket creation, exception workflow, SLA tracking, dedup by fingerprint.
- Continuous monitoring automation for registered targets.
- Rebuilt operator console with overview, inventory, jobs, reporting, tool lab, and settings views.

## Quickstart

Install dependencies from the project root or from `backend/`.

Windows:

```powershell
cd "X:\College Project"
python -m venv backend\.venv
.\backend\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Linux:

```bash
cd ~/path/to/project
python3 -m venv backend/.venv
source backend/.venv/bin/activate
pip install -r requirements.txt
cd backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Frontend:

```bash
cd frontend
python3 -m http.server 5173
```

Open:

- `http://127.0.0.1:5173` for the frontend
- `http://127.0.0.1:8000/docs` for the API docs
- `http://127.0.0.1:8000/health` for a health check

## VS Code

The workspace now includes:

- `.vscode/tasks.json`
- `.vscode/launch.json`

Useful tasks:

- `ASM Backend`
- `ASM Frontend`
- `ASM Reset Runtime Data`
- `ASM Fresh Database`

You can run them from `Terminal -> Run Task` inside VS Code, or use the helper scripts in `scripts/` for the same flows from a terminal.

## Helper Scripts

Windows PowerShell:

```powershell
.\scripts\run-backend.ps1
.\scripts\run-frontend.ps1
.\scripts\reset-runtime.ps1
.\scripts\fresh-start.ps1
```

Linux:

```bash
./scripts/run-backend.sh
./scripts/run-frontend.sh
./scripts/reset-runtime.sh
./scripts/fresh-start.sh
```

`reset-runtime` clears runtime data through the API while keeping the current database file.

`fresh-start` removes `backend/asm.db` for a full clean restart.

## Notes

- All scans must be executed only against authorized targets.
- The platform now defaults to `auto` mode so installed native scanner binaries run when available and Python fallback stays available when they are not.
- The fallback path uses built-in Python DNS, HTTP, TLS, and port checks instead of invented placeholder results.
- Native binaries are opt-in. Set `ASM_NATIVE_TOOL_MODE=auto` or `ASM_NATIVE_TOOL_MODE=native` if you want the platform to call installed scanner binaries directly.

## Environment Variables

- `ASM_DATABASE_URL`: database connection string, default `sqlite:///./asm.db`
- `ASM_EPSS_CSV`: EPSS CSV path, default `./data/epss.csv`
- `ASM_KEV_JSON`: CISA KEV JSON path, default `./data/kev.json`
- `ASM_EXPLOITDB_CSV`: Exploit-DB CSV path, default `./data/exploitdb.csv`
- `ASM_NATIVE_TOOL_MODE`: `auto`, `fallback`, or `native`, default `auto`
- `ASM_TOOL_TIMEOUT`: per-tool timeout in seconds, default `20`
- `ASM_CORS_ORIGINS`: comma-separated frontend origins
- `ASM_DEFAULT_MONITOR_CRON`: default monitoring schedule
- `ASM_NODE_NAME`: local worker name
- `ASM_SCHEDULER_INTERVAL`: scheduler polling interval in seconds
- `ASM_WORKER_COUNT`: local worker thread count

## EPSS

Place a CSV file with headers `cve,epss` (or `cve_id,epss_score`) at the path in `ASM_EPSS_CSV`.
The backend loads this on startup and you can refresh it via `POST /epss/refresh`.

## Operational Notes

- Fallback mode is the default safe mode. It keeps the platform functional even when local binaries are missing.
- Old targets stored as full URLs are normalized on backend startup when there is no naming conflict.
- Use `POST /jobs/recover` or the frontend `Recover stuck jobs` action to requeue stale jobs after an unclean shutdown.
- Non-running jobs can be deleted from the UI to clear out bad historical runs without removing target inventory.
- Use `POST /system/reset-data` or the frontend `Reset all runtime data` action for a clean restart without deleting code or EPSS data.

## Git Hygiene

The repository now includes a root `.gitignore` for:

- Python virtual environments
- `__pycache__` and compiled Python artifacts
- local SQLite databases
- editor-only files

If older commits already tracked local environments, caches, or databases, remove them once from the Git index:

```powershell
git rm -r --cached .venv backend/.venv backend/app/__pycache__
git rm --cached asm.db backend/*.db
git commit -m "Clean tracked runtime artifacts"
```

This does not delete your local files. It only stops Git from tracking them.
