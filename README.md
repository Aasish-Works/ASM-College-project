# Enterprise Attack Surface Management (ASM) Platform

Enterprise-grade ASM platform for authorized security testing and defense research. This build includes:

- EPSS + contextual risk scoring (exploitability + business criticality + exposure context).
- Scan orchestration with job queue, retry/backoff, prioritization, and scanner-node heartbeat.
- Tool execution pipeline for Nmap, Masscan, Subfinder, Assetfinder, Nikto, Nuclei, Amass, httpx, Naabu, and Wafw00f with fallback mode.
- Vulnerability lifecycle operations: assignment, ticket creation, exception workflow, SLA tracking, dedup by fingerprint.
- Continuous monitoring automation for registered targets.
- Elegant frontend with target intelligence drill-down.

## Quickstart

Install dependencies from the project root or from `backend/`.

Windows:

```powershell
cd "X:\College Project"
python -m venv backend\.venv
.\backend\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd backend
uvicorn app.main:app --reload
```

Linux:

```bash
cd ~/path/to/project
python3 -m venv backend/.venv
source backend/.venv/bin/activate
pip install -r requirements.txt
cd backend
uvicorn app.main:app --reload
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

## Notes

- All scans must be executed only against authorized targets.
- Tool fallback mode is enabled by default when binaries are unavailable.
- If you started the backend before these schema updates, delete `asm.db` to recreate tables.

## Environment Variables

- `ASM_DATABASE_URL`: database connection string, default `sqlite:///./asm.db`
- `ASM_EPSS_CSV`: EPSS CSV path, default `./data/epss.csv`
- `ASM_KEV_JSON`: CISA KEV JSON path, default `./data/kev.json`
- `ASM_EXPLOITDB_CSV`: Exploit-DB CSV path, default `./data/exploitdb.csv`
- `ASM_NATIVE_TOOL_MODE`: `fallback`, `native`, or `auto`, default `fallback`
- `ASM_TOOL_TIMEOUT`: per-tool timeout in seconds, default `8`
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
