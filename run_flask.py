"""Chạy riêng Flask Dashboard với cấu hình PostgreSQL trong config.yaml."""

import os
import sys
from datetime import datetime

project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import yaml

from src.dashboard import APP_CONTEXT, run_dashboard
from src.db import init_db
from src.pg_store import PostgresStore


def main() -> None:
    config_path = os.environ.get("AI_IDS_CONFIG", "config.yaml")
    with open(config_path, "r", encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file) or {}

    init_db(config.get("database", {}))

    # Dashboard đọc cảnh báo từ PostgreSQL; khởi tạo store để /api/status
    # hiển thị số liệu từng chặng của pipeline.
    pg_store = PostgresStore(config.get("database", {}))
    if pg_store.enabled:
        pg_store.init_schema()

    APP_CONTEXT["config"] = config
    APP_CONTEXT["config_path"] = config_path
    APP_CONTEXT["pg_store"] = pg_store
    APP_CONTEXT["session_started_at"] = datetime.now().isoformat()

    dashboard_cfg = config.get("dashboard", {})
    run_dashboard(
        host=dashboard_cfg.get("host", "0.0.0.0"),
        port=int(dashboard_cfg.get("port", 5000)),
        debug=bool(dashboard_cfg.get("debug", False)),
    )


if __name__ == "__main__":
    main()
