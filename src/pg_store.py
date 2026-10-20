"""
Optional PostgreSQL store for raw Suricata events and separately mirrored alerts.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Any

logger = logging.getLogger("AI_IDS.PgStore")

try:
    import psycopg2
    import psycopg2.extras
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False
    psycopg2 = None  # type: ignore


class PostgresStore:
    def __init__(self, config: dict):
        self.config = config or {}
        self.enabled: bool = bool(self.config.get("enabled", False))
        self.dsn: str = self.config.get("dsn", "")
        self.host = self.config.get("host", "127.0.0.1")
        self.port = int(self.config.get("port", 5432))
        self.dbname = self.config.get("dbname", "ids_system")
        self.user = self.config.get("user", "ids_user")
        self.password = self.config.get("password", "")
        self.table_logs = self.config.get("table_logs", "raw_logs")
        self.table_alerts = self.config.get("table_alerts", "pg_alerts")
        self._lock = threading.Lock()
        self._conn = None
        self.last_error = ""
        self.saved_logs = 0
        self.saved_alerts = 0

    def _connect(self):
        if not HAS_PSYCOPG2:
            raise RuntimeError("thieu psycopg2-binary")
        if self._conn is not None:
            try:
                cur = self._conn.cursor()
                cur.execute("SELECT 1")
                cur.close()
                return self._conn
            except Exception:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
        if self.dsn:
            self._conn = psycopg2.connect(self.dsn)
        else:
            self._conn = psycopg2.connect(
                host=self.host, port=self.port, dbname=self.dbname,
                user=self.user, password=self.password, connect_timeout=5,
            )
        self._conn.autocommit = True
        return self._conn

    def init_schema(self):
        if not self.enabled:
            return False
        try:
            conn = self._connect()
            cur = conn.cursor()
            cur.execute(
                f"CREATE TABLE IF NOT EXISTS {self.table_logs} ("
                "id SERIAL PRIMARY KEY, ts TIMESTAMPTZ, event_type TEXT, "
                "src_ip TEXT, dest_ip TEXT, sensor TEXT, raw JSONB)"
            )
            cur.execute(f"CREATE INDEX IF NOT EXISTS idx_logs_ts ON {self.table_logs}(ts)")
            cur.execute(f"CREATE INDEX IF NOT EXISTS idx_logs_src ON {self.table_logs}(src_ip)")
            cur.execute(
                f"CREATE TABLE IF NOT EXISTS {self.table_alerts} ("
                "id SERIAL PRIMARY KEY, ts TIMESTAMPTZ DEFAULT NOW(), src_ip TEXT NOT NULL, "
                "attack_type TEXT NOT NULL, score DOUBLE PRECISION, "
                "severity TEXT, status TEXT, source_alert_id INTEGER)"
            )
            cur.close()
            self.last_error = ""
            return True
        except Exception as e:
            self.last_error = str(e)
            return False

    def save_event(self, event):
        if not self.enabled:
            return False
        try:
            import psycopg2.extras as pg_extras
            conn = self._connect()
            cur = conn.cursor()
            ts_raw = event.get("timestamp") or event.get("sync_timestamp")
            try:
                ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00")) if ts_raw else datetime.now()
            except Exception:
                ts = datetime.now()
            cur.execute(
                f"INSERT INTO {self.table_logs} (ts, event_type, src_ip, dest_ip, sensor, raw) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (ts, event.get("event_type"), event.get("src_ip"), event.get("dest_ip"),
                 event.get("sensor") or "suricata@pfsense", pg_extras.Json(event)),
            )
            cur.close()
            with self._lock:
                self.saved_logs += 1
            return True
        except Exception as e:
            self.last_error = str(e)
            try:
                if self._conn:
                    self._conn.close()
            except Exception:
                pass
            self._conn = None
            return False

    def save_alert(self, src_ip, attack_type, score, severity, status="pending", source_alert_id=None):
        if not self.enabled:
            return False
        try:
            conn = self._connect()
            cur = conn.cursor()
            cur.execute(
                f"INSERT INTO {self.table_alerts} (src_ip, attack_type, score, severity, status, source_alert_id) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (src_ip, attack_type, float(score), severity, status, source_alert_id),
            )
            cur.close()
            with self._lock:
                self.saved_alerts += 1
            return True
        except Exception as e:
            self.last_error = str(e)
            try:
                if self._conn:
                    self._conn.close()
            except Exception:
                pass
            self._conn = None
            return False

    def get_status(self):
        return {
            "enabled": self.enabled, "has_driver": HAS_PSYCOPG2,
            "host": self.host, "port": self.port, "dbname": self.dbname,
            "saved_logs": self.saved_logs, "saved_alerts": self.saved_alerts,
            "last_error": self.last_error,
        }
