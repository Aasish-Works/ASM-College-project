from __future__ import annotations

import os
from dataclasses import dataclass, field


def _split_csv(value: str | None, default: list[str]) -> list[str]:
    if not value:
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(slots=True)
class Settings:
    database_url: str = os.getenv("ASM_DATABASE_URL", "sqlite:///./asm.db")
    epss_csv_path: str = os.getenv("ASM_EPSS_CSV", "./data/epss.csv")
    kev_json_path: str = os.getenv("ASM_KEV_JSON", "./data/kev.json")
    exploitdb_csv_path: str = os.getenv("ASM_EXPLOITDB_CSV", "./data/exploitdb.csv")
    native_tool_mode: str = os.getenv("ASM_NATIVE_TOOL_MODE", "fallback").lower()
    tool_timeout_seconds: int = int(os.getenv("ASM_TOOL_TIMEOUT", "8"))
    cors_origins: list[str] = field(
        default_factory=lambda: _split_csv(
            os.getenv("ASM_CORS_ORIGINS"),
            ["http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:8000"],
        )
    )
    default_monitor_cron: str = os.getenv("ASM_DEFAULT_MONITOR_CRON", "0 */6 * * *")
    local_node_name: str = os.getenv("ASM_NODE_NAME", "local-worker-01")
    scheduler_interval_seconds: int = int(os.getenv("ASM_SCHEDULER_INTERVAL", "15"))
    worker_count: int = int(os.getenv("ASM_WORKER_COUNT", "2"))


settings = Settings()
