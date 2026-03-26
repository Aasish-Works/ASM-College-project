# Enterprise Attack Surface Management (ASM) Platform

Enterprise-grade ASM platform for authorized security testing and defense research. This build includes:

- EPSS + contextual risk scoring (exploitability + business criticality + exposure context).
- Scan orchestration with job queue, retry/backoff, prioritization, and scanner-node heartbeat.
- Tool execution pipeline for Nmap, Masscan, Subfinder, Assetfinder, Nikto, Nuclei, Amass, httpx, Naabu, and Wafw00f with fallback mode.
- Vulnerability lifecycle operations: assignment, ticket creation, exception workflow, SLA tracking, dedup by fingerprint.
- Continuous monitoring automation for registered targets.
- Elegant frontend with target intelligence drill-down.

## Quickstart

Backend:

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

If you start from the project root, run:

```bash
cd backend
uvicorn app.main:app --reload
```

Frontend:

```bash
cd frontend
python -m http.server 5173
```

Open `http://localhost:5173` in the browser.

## Notes

- All scans must be executed only against authorized targets.
- Tool fallback mode is enabled by default when binaries are unavailable.
- If you started the backend before these schema updates, delete `asm.db` to recreate tables.

## Environment Variables

- `ASM_DB_URL`: database connection string (default `sqlite:///./asm.db`)
- `ASM_TOOL_FALLBACK`: `true` or `false`
- `ASM_SCAN_CONCURRENCY`: number of scan workers
- `ASM_HEARTBEAT_TIMEOUT`: seconds before node marked offline
- `ASM_MONITORING_POLL`: seconds between monitoring checks
- `ASM_MONITORING_INTERVAL_MINUTES`: default monitoring interval
- `ASM_EPSS_CSV`: path to EPSS CSV (default `./data/epss.csv`)

## EPSS

Place a CSV file with headers `cve,epss` (or `cve_id,epss_score`) at the path in `ASM_EPSS_CSV`.
The backend loads this on startup and you can refresh it via `POST /epss/refresh`.
