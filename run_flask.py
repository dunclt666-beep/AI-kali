"""Chạy riêng Flask Dashboard với cấu hình PostgreSQL trong config.yaml."""

import os
import sys

project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import yaml

from src.dashboard import APP_CONTEXT, run_dashboard
from src.db import init_db


def main() -> None:
    config_path = os.environ.get("AI_IDS_CONFIG", "config.yaml")
    with open(config_path, "r", encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file) or {}

    init_db(config.get("database", {}))

    APP_CONTEXT["config"] = config
    APP_CONTEXT["config_path"] = config_path

    dashboard_cfg = config.get("dashboard", {})
    run_dashboard(
        host=dashboard_cfg.get("host", "0.0.0.0"),
        port=int(dashboard_cfg.get("port", 5000)),
        debug=bool(dashboard_cfg.get("debug", False)),
    )


if __name__ == "__main__":
    main()
