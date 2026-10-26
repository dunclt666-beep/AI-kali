"""
PostgreSQL data layer cho pipeline AI-IDS.

Luồng dữ liệu:
    Suricata eve.json -> LogCollector -> raw_events
    raw_events -> AI Worker -> network_features + ai_predictions + alerts
    alerts / raw_events -> Flask Dashboard

Module dùng chung schema với hệ thống hiện có trong database ``ids_system``:
``raw_events``, ``network_features``, ``ai_predictions`` và ``alerts``.
Nhờ vậy dữ liệu cũ (nếu có) vẫn đọc được và dashboard ai_ids/test6 dùng cùng nguồn.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("AI_IDS.PgStore")

try:
    import psycopg2
    import psycopg2.extras
    HAS_PSYCOPG2 = True
except ImportError:  # pragma: no cover - chỉ xảy ra khi thiếu driver
    HAS_PSYCOPG2 = False
    psycopg2 = None  # type: ignore


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_event_timestamp(value: Any) -> datetime:
    """Chuyển timestamp EVE (ISO8601, có thể +0000) sang datetime có timezone."""
    if isinstance(value, datetime):
        return value
    if value:
        text = str(value).strip()
        try:
            # Suricata ghi dạng 2026-10-12T07:15:23.123456+0000 (thiếu dấu ':' ở tz)
            if len(text) > 5 and text[-5] in ("+", "-") and ":" not in text[-5:]:
                text = text[:-2] + ":" + text[-2:]
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except Exception:
            pass
    return _utc_now()


class PostgresStore:
    """Truy cập PostgreSQL cho toàn bộ pipeline (collector + worker + dashboard)."""

    def __init__(self, config: dict):
        self.config = config or {}
        # Mặc định BẬT khi đã có thông tin kết nối. Chỉ tắt khi cấu hình ghi rõ
        # `enabled: false`. Trước đây mặc định False khiến collector âm thầm
        # không ghi được sự kiện nào vào PostgreSQL.
        if "enabled" in self.config:
            self.enabled = bool(self.config.get("enabled"))
        else:
            self.enabled = bool(
                self.config.get("dsn")
                or self.config.get("dbname")
                or self.config.get("host")
            )
        self.dsn: str = self.config.get("dsn", "")
        self.host = self.config.get("host", "127.0.0.1")
        self.port = int(self.config.get("port", 5432))
        self.dbname = self.config.get("dbname", "ids_system")
        self.user = self.config.get("user", "ids_user")
        self.password = self.config.get("password", "")
        self.connect_timeout = int(self.config.get("connect_timeout", 5))

        # Tên bảng có thể ghi đè, nhưng mặc định dùng schema chuẩn của hệ thống.
        self.table_logs = self.config.get("table_logs", "raw_events")
        self.table_features = self.config.get("table_features", "network_features")
        self.table_predictions = self.config.get("table_predictions", "ai_predictions")
        self.table_alerts = self.config.get("table_alerts", "alerts")

        self._lock = threading.RLock()
        self._conn = None
        self.last_error = ""
        self.saved_logs = 0
        self.duplicate_logs = 0
        self.saved_alerts = 0
        self.saved_predictions = 0
        self.saved_features = 0

    # ── Kết nối ───────────────────────────────────────────────────────────

    def _connect(self):
        if not HAS_PSYCOPG2:
            raise RuntimeError("Thiếu psycopg2-binary: pip install psycopg2-binary")
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
            self._conn = psycopg2.connect(self.dsn, connect_timeout=self.connect_timeout)
        else:
            self._conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                dbname=self.dbname,
                user=self.user,
                password=self.password,
                connect_timeout=self.connect_timeout,
            )
        self._conn.autocommit = True
        return self._conn

    def _execute(self, sql: str, params: tuple | dict | None = None):
        """Thực thi một câu lệnh và trả về cursor (đã fetch sẵn nếu cần)."""
        with self._lock:
            conn = self._connect()
            cur = conn.cursor()
            cur.execute(sql, params)
            return cur

    # ── Schema ────────────────────────────────────────────────────────────

    def init_schema(self) -> bool:
        """Tạo/cập nhật schema tối thiểu cho pipeline.

        An toàn với database đã có dữ liệu: chỉ dùng CREATE ... IF NOT EXISTS
        và ALTER TABLE ... ADD COLUMN IF NOT EXISTS.
        """
        if not self.enabled:
            self.last_error = "PostgresStore đang tắt (database.enabled=false)"
            return False
        try:
            with self._lock:
                conn = self._connect()
                cur = conn.cursor()

                # 1. raw_events – log thô Suricata (nguồn sự thật duy nhất)
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self.table_logs} (
                        id BIGSERIAL PRIMARY KEY,
                        event_timestamp TIMESTAMPTZ NOT NULL,
                        received_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
                        source VARCHAR(64) NOT NULL DEFAULT 'pfsense_suricata',
                        event_type VARCHAR(32) NOT NULL,
                        src_ip VARCHAR(64),
                        src_port INTEGER,
                        dest_ip VARCHAR(64),
                        dest_port INTEGER,
                        protocol VARCHAR(16),
                        signature TEXT,
                        category TEXT,
                        severity INTEGER,
                        raw_json JSONB NOT NULL,
                        event_hash VARCHAR(64) NOT NULL,
                        processed BOOLEAN NOT NULL DEFAULT FALSE,
                        processed_at TIMESTAMPTZ
                    )
                    """
                )
                # Các cột mở rộng phục vụ claim/retry của worker.
                cur.execute(
                    f"ALTER TABLE {self.table_logs} "
                    "ADD COLUMN IF NOT EXISTS processing_status TEXT"
                )
                cur.execute(
                    f"ALTER TABLE {self.table_logs} "
                    "ADD COLUMN IF NOT EXISTS processing_attempts INTEGER DEFAULT 0"
                )
                cur.execute(
                    f"ALTER TABLE {self.table_logs} "
                    "ADD COLUMN IF NOT EXISTS processing_started_at TIMESTAMPTZ"
                )
                cur.execute(
                    f"ALTER TABLE {self.table_logs} "
                    "ADD COLUMN IF NOT EXISTS lease_until TIMESTAMPTZ"
                )
                cur.execute(
                    f"ALTER TABLE {self.table_logs} "
                    "ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ"
                )
                cur.execute(
                    f"ALTER TABLE {self.table_logs} "
                    "ADD COLUMN IF NOT EXISTS last_error TEXT"
                )
                # Đồng bộ trạng thái cho các bản ghi cũ (trước khi thêm cột).
                cur.execute(
                    f"""
                    UPDATE {self.table_logs}
                    SET processing_status = CASE WHEN processed THEN 'processed' ELSE 'pending' END
                    WHERE processing_status IS NULL
                    """
                )
                cur.execute(
                    f"CREATE UNIQUE INDEX IF NOT EXISTS uq_raw_events_hash "
                    f"ON {self.table_logs}(event_hash)"
                )
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_raw_events_timestamp "
                    f"ON {self.table_logs}(event_timestamp DESC)"
                )
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_raw_events_unprocessed "
                    f"ON {self.table_logs}(id) WHERE processed = FALSE"
                )
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_raw_events_status "
                    f"ON {self.table_logs}(processing_status)"
                )
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_raw_events_src_ip "
                    f"ON {self.table_logs}(src_ip)"
                )

                # 2. network_features – vector đặc trưng do AI Worker trích xuất
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self.table_features} (
                        id BIGSERIAL PRIMARY KEY,
                        event_id BIGINT REFERENCES {self.table_logs}(id) ON DELETE SET NULL,
                        window_id VARCHAR(64),
                        event_timestamp TIMESTAMPTZ NOT NULL,
                        src_ip VARCHAR(64) NOT NULL,
                        dest_ip VARCHAR(64),
                        dest_port INTEGER,
                        flow_duration DOUBLE PRECISION DEFAULT 0.0,
                        packets_to_server INTEGER DEFAULT 0,
                        packets_to_client INTEGER DEFAULT 0,
                        bytes_to_server BIGINT DEFAULT 0,
                        bytes_to_client BIGINT DEFAULT 0,
                        packet_rate DOUBLE PRECISION DEFAULT 0.0,
                        byte_rate DOUBLE PRECISION DEFAULT 0.0,
                        connection_rate DOUBLE PRECISION DEFAULT 0.0,
                        unique_destination_ports INTEGER DEFAULT 1,
                        short_flow_count INTEGER DEFAULT 0,
                        http_request_count INTEGER DEFAULT 0,
                        http_error_ratio DOUBLE PRECISION DEFAULT 0.0,
                        failed_login_count INTEGER DEFAULT 0,
                        param_entropy DOUBLE PRECISION DEFAULT 0.0,
                        sql_keyword_count INTEGER DEFAULT 0,
                        special_char_count INTEGER DEFAULT 0,
                        user_agent_flag INTEGER DEFAULT 0,
                        related_alert_count INTEGER DEFAULT 0,
                        feature_schema_version VARCHAR(20) NOT NULL DEFAULT 'v1.0',
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    )
                    """
                )
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_features_event_id "
                    f"ON {self.table_features}(event_id)"
                )
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_features_timestamp "
                    f"ON {self.table_features}(event_timestamp DESC)"
                )

                # 3. ai_predictions – kết quả suy luận của worker AI
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self.table_predictions} (
                        id BIGSERIAL PRIMARY KEY,
                        event_id BIGINT REFERENCES {self.table_logs}(id) ON DELETE SET NULL,
                        window_id VARCHAR(64),
                        model_name VARCHAR(50) NOT NULL,
                        model_version VARCHAR(50) NOT NULL,
                        predicted_label VARCHAR(50) NOT NULL,
                        confidence DOUBLE PRECISION NOT NULL,
                        risk_level VARCHAR(20) NOT NULL,
                        inference_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
                        inference_latency_ms DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                        explanation JSONB,
                        feature_schema_version VARCHAR(20) NOT NULL DEFAULT 'v1.0'
                    )
                    """
                )
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_predictions_event "
                    f"ON {self.table_predictions}(event_id)"
                )
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_predictions_timestamp "
                    f"ON {self.table_predictions}(inference_timestamp DESC)"
                )

                # 4. alerts – cảnh báo đã gom nhóm, dashboard đọc trực tiếp
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self.table_alerts} (
                        id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                        ts TEXT,
                        src_ip TEXT NOT NULL,
                        dest_ip VARCHAR(64),
                        attack_type TEXT NOT NULL,
                        score DOUBLE PRECISION,
                        severity TEXT NOT NULL,
                        status TEXT NOT NULL,
                        decided_by TEXT,
                        decided_at TEXT,
                        alert_timestamp TIMESTAMPTZ DEFAULT now(),
                        source_of_detection VARCHAR(50) DEFAULT 'Hybrid_Ensemble',
                        confidence DOUBLE PRECISION DEFAULT 1.0,
                        evidence JSONB
                    )
                    """
                )
                for column, ddl in (
                    ("dest_ip", "VARCHAR(64)"),
                    ("alert_timestamp", "TIMESTAMPTZ DEFAULT now()"),
                    ("source_of_detection", "VARCHAR(50) DEFAULT 'Hybrid_Ensemble'"),
                    ("confidence", "DOUBLE PRECISION DEFAULT 1.0"),
                    ("evidence", "JSONB"),
                ):
                    cur.execute(
                        f"ALTER TABLE {self.table_alerts} "
                        f"ADD COLUMN IF NOT EXISTS {column} {ddl}"
                    )
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_alerts_ip "
                    f"ON {self.table_alerts}(src_ip)"
                )
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_alerts_status "
                    f"ON {self.table_alerts}(status)"
                )
                cur.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_alerts_timestamp "
                    f"ON {self.table_alerts}(alert_timestamp DESC)"
                )

                cur.close()
            self.last_error = ""
            return True
        except Exception as exc:  # pragma: no cover - phụ thuộc PostgreSQL
            self.last_error = str(exc)
            logger.error("Không khởi tạo được schema PostgreSQL: %s", exc)
            self._drop_connection()
            return False

    # ── Collector: ghi log thô ────────────────────────────────────────────

    @staticmethod
    def _canonical_hash(event: dict) -> str:
        """SHA-256 của JSON chuẩn hóa, bỏ các trường thời gian dễ thay đổi."""
        volatile = {"timestamp", "sync_timestamp", "event_timestamp"}
        sanitized = {k: v for k, v in event.items() if k not in volatile}
        canonical = json.dumps(
            sanitized, separators=(",", ":"), sort_keys=True, default=str
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def save_event(self, event: dict) -> bool:
        """Ghi một sự kiện Suricata vào raw_events (deduplicate bằng event_hash).

        Trả về True nếu bản ghi mới được thêm hoặc đã tồn tại trước đó.
        """
        if not self.enabled:
            return False
        if not isinstance(event, dict):
            return False
        try:
            alert_obj = event.get("alert") or {}
            signature = event.get("signature") or alert_obj.get("signature")
            category = event.get("category") or alert_obj.get("category")
            severity = event.get("severity") or alert_obj.get("severity")
            try:
                severity = int(severity) if severity is not None else None
            except (TypeError, ValueError):
                severity = None

            raw_json = json.dumps(event, default=str)
            event_hash = self._canonical_hash(event)

            with self._lock:
                conn = self._connect()
                cur = conn.cursor()
                cur.execute(
                    f"""
                    INSERT INTO {self.table_logs} (
                        event_timestamp, received_timestamp, source, event_type,
                        src_ip, src_port, dest_ip, dest_port, protocol,
                        signature, category, severity, raw_json, event_hash,
                        processed, processing_status
                    ) VALUES (
                        %s, now(), %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        FALSE, 'pending'
                    )
                    ON CONFLICT (event_hash) DO NOTHING
                    RETURNING id
                    """,
                    (
                        _parse_event_timestamp(
                            event.get("timestamp") or event.get("sync_timestamp")
                        ),
                        event.get("source")
                        or event.get("sensor")
                        or "pfsense_suricata",
                        event.get("event_type") or "unknown",
                        event.get("src_ip"),
                        event.get("src_port"),
                        event.get("dest_ip"),
                        event.get("dest_port"),
                        event.get("proto") or event.get("protocol"),
                        signature,
                        category,
                        severity,
                        raw_json,
                        event_hash,
                    ),
                )
                inserted = cur.fetchone()
                cur.close()
                if inserted:
                    self.saved_logs += 1
                else:
                    self.duplicate_logs += 1
            self.last_error = ""
            return True
        except Exception as exc:
            self.last_error = str(exc)
            logger.error("Không ghi được sự kiện vào PostgreSQL: %s", exc)
            self._drop_connection()
            return False

    # ── Worker: claim / cập nhật trạng thái ──────────────────────────────

    def claim_pending(self, limit: int = 20) -> list[dict]:
        """Nhận các sự kiện chưa xử lý theo cơ chế lease.

        - Chỉ lấy bản ghi ``pending`` (hoặc đã quá hạn retry).
        - ``FOR UPDATE SKIP LOCKED`` cho phép chạy nhiều worker song song.
        - Bản ghi đang ``processing`` quá 5 phút (worker chết) được trả lại queue.
        """
        if not self.enabled:
            return []
        try:
            with self._lock:
                conn = self._connect()
                cur = conn.cursor()
                cur.execute(
                    f"""
                    UPDATE {self.table_logs}
                    SET processing_status = 'pending', lease_until = NULL
                    WHERE processing_status = 'processing'
                      AND lease_until IS NOT NULL
                      AND lease_until < now()
                    """
                )
                cur.execute(
                    f"""
                    WITH cte AS (
                        SELECT id FROM {self.table_logs}
                        WHERE processed = FALSE
                          AND COALESCE(processing_status, 'pending') = 'pending'
                          AND (next_retry_at IS NULL OR next_retry_at <= now())
                        ORDER BY id
                        FOR UPDATE SKIP LOCKED
                        LIMIT %s
                    )
                    UPDATE {self.table_logs} r
                    SET processing_status = 'processing',
                        processing_started_at = now(),
                        lease_until = now() + INTERVAL '5 minutes',
                        processing_attempts = COALESCE(r.processing_attempts, 0) + 1
                    FROM cte
                    WHERE r.id = cte.id
                    RETURNING r.*;
                    """,
                    (int(limit),),
                )
                rows = cur.fetchall()
                colnames = [desc[0] for desc in cur.description]
                cur.close()
            return [dict(zip(colnames, row)) for row in rows]
        except Exception as exc:
            self.last_error = str(exc)
            logger.error("Không claim được sự kiện từ PostgreSQL: %s", exc)
            self._drop_connection()
            return []

    def set_processing_status(
        self,
        event_id: int,
        status: str,
        error_msg: str | None = None,
        next_retry_at: Any = None,
    ) -> bool:
        """Cập nhật trạng thái xử lý của một sự kiện.

        status: pending | processing | processed | failed
        - ``processed``: giữ nguyên ``processed = TRUE``.
        - ``pending``: trả lại queue kèm last_error/next_retry_at.
        - ``failed``: đánh dấu thất bại vĩnh viễn, không retry nữa.
        """
        if not self.enabled or event_id is None:
            return False
        try:
            with self._lock:
                conn = self._connect()
                cur = conn.cursor()
                if status == "processed":
                    cur.execute(
                        f"""
                        UPDATE {self.table_logs}
                        SET processed = TRUE, processed_at = now(),
                            processing_status = 'processed',
                            lease_until = NULL, last_error = NULL
                        WHERE id = %s
                        """,
                        (event_id,),
                    )
                elif status == "failed":
                    cur.execute(
                        f"""
                        UPDATE {self.table_logs}
                        SET processed = TRUE, processed_at = now(),
                            processing_status = 'failed',
                            lease_until = NULL, last_error = %s
                        WHERE id = %s
                        """,
                        (error_msg, event_id),
                    )
                elif status == "pending":
                    cur.execute(
                        f"""
                        UPDATE {self.table_logs}
                        SET processed = FALSE, processed_at = NULL,
                            processing_status = 'pending',
                            lease_until = NULL,
                            last_error = %s,
                            next_retry_at = %s
                        WHERE id = %s
                        """,
                        (error_msg, next_retry_at, event_id),
                    )
                else:
                    cur.execute(
                        f"""
                        UPDATE {self.table_logs}
                        SET processing_status = %s
                        WHERE id = %s
                        """,
                        (status, event_id),
                    )
                cur.close()
            return True
        except Exception as exc:
            self.last_error = str(exc)
            logger.error("Không cập nhật được trạng thái event %s: %s", event_id, exc)
            self._drop_connection()
            return False

    # ── Worker: đặc trưng / dự đoán / cảnh báo ───────────────────────────

    def save_features(self, event_id: int, event: dict, features: dict) -> bool:
        """Lưu vector đặc trưng vào network_features."""
        if not self.enabled:
            return False
        try:
            flow = event.get("flow") or {}
            http_obj = event.get("http") or {}
            record = {
                "event_id": event_id,
                "window_id": None,
                "event_timestamp": _parse_event_timestamp(
                    event.get("timestamp") or event.get("sync_timestamp")
                ),
                "src_ip": event.get("src_ip") or features.get("src_ip") or "0.0.0.0",
                "dest_ip": event.get("dest_ip"),
                "dest_port": event.get("dest_port"),
                "flow_duration": float(features.get("flow_duration", 0.0) or 0.0),
                "packets_to_server": int(flow.get("pkts_toserver", 0) or 0),
                "packets_to_client": int(flow.get("pkts_toclient", 0) or 0),
                "bytes_to_server": int(flow.get("bytes_toserver", 0) or 0),
                "bytes_to_client": int(flow.get("bytes_toclient", 0) or 0),
                "packet_rate": float(features.get("pkts_per_sec", 0.0) or 0.0),
                "byte_rate": float(features.get("bytes_per_sec", 0.0) or 0.0),
                "connection_rate": float(features.get("concurrent_flows", 0.0) or 0.0),
                "unique_destination_ports": int(
                    features.get("unique_dst_ports", 1) or 1
                ),
                "short_flow_count": int(features.get("short_flow_count", 0) or 0),
                "http_request_count": int(
                    features.get("window_http_count", 1 if http_obj else 0) or 0
                ),
                "http_error_ratio": float(features.get("ratio_4xx", 0.0) or 0.0),
                "failed_login_count": int(
                    features.get("login_fail_count", 0) or 0
                ),
                "param_entropy": float(features.get("param_entropy", 0.0) or 0.0),
                "sql_keyword_count": int(
                    features.get("sql_keyword_count", 0) or 0
                ),
                "special_char_count": int(
                    features.get("special_char_count", 0) or 0
                ),
                "user_agent_flag": int(features.get("user_agent_flag", 0) or 0),
                "related_alert_count": int(
                    features.get("suricata_alert_count", 0) or 0
                ),
                "feature_schema_version": "v1.0",
            }
            columns = ", ".join(record.keys())
            placeholders = ", ".join(["%s"] * len(record))
            with self._lock:
                conn = self._connect()
                cur = conn.cursor()
                # Idempotent: nếu event đã có feature (ví dụ do worker khác xử lý)
                # thì bỏ qua thay vì tạo bản ghi trùng.
                cur.execute(
                    f"SELECT 1 FROM {self.table_features} WHERE event_id = %s LIMIT 1",
                    (event_id,),
                )
                if cur.fetchone():
                    cur.close()
                    return True
                cur.execute(
                    f"INSERT INTO {self.table_features} ({columns}) "
                    f"VALUES ({placeholders})",
                    tuple(record.values()),
                )
                cur.close()
                self.saved_features += 1
            return True
        except Exception as exc:
            self.last_error = str(exc)
            logger.error("Không lưu được features cho event %s: %s", event_id, exc)
            self._drop_connection()
            return False

    def save_prediction(
        self,
        event_id: int,
        model_name: str,
        model_version: str,
        predicted_label: str,
        confidence: float,
        model_sha256: str | None = None,
        risk_level: str | None = None,
        inference_latency_ms: float | None = None,
        feature_schema_version: str | None = None,
        explanation: Any = None,
        window_id: str | None = None,
    ) -> bool:
        """Ghi kết quả AI vào ai_predictions (tương thích schema hiện có)."""
        if not self.enabled:
            return False
        try:
            if isinstance(explanation, str):
                explanation_json = explanation
            else:
                explanation_json = json.dumps(explanation or {}, default=str)
            with self._lock:
                conn = self._connect()
                cur = conn.cursor()
                # Idempotent theo (event_id, model_name, model_version).
                cur.execute(
                    f"""
                    SELECT 1 FROM {self.table_predictions}
                    WHERE event_id = %s AND model_name = %s AND model_version = %s
                    LIMIT 1
                    """,
                    (event_id, model_name, model_version),
                )
                if cur.fetchone():
                    cur.close()
                    return True
                cur.execute(
                    f"""
                    INSERT INTO {self.table_predictions} (
                        event_id, window_id, model_name, model_version,
                        predicted_label, confidence, risk_level,
                        inference_timestamp, inference_latency_ms,
                        explanation, feature_schema_version
                    ) VALUES (
                        %s, %s, %s, %s,
                        %s, %s, %s,
                        now(), %s,
                        %s, %s
                    )
                    """,
                    (
                        event_id,
                        window_id,
                        model_name,
                        model_version,
                        predicted_label,
                        float(confidence or 0.0),
                        risk_level or "INFO",
                        float(inference_latency_ms or 0.0),
                        explanation_json,
                        feature_schema_version or "v1.0",
                    ),
                )
                cur.close()
                self.saved_predictions += 1
            return True
        except Exception as exc:
            self.last_error = str(exc)
            logger.error(
                "Không lưu được prediction cho event %s: %s", event_id, exc
            )
            self._drop_connection()
            return False

    def save_alert(
        self,
        src_ip: str,
        dest_ip: str | None,
        attack_type: str,
        score: float,
        severity: str,
        status: str = "pending",
        source_alert_id: int | None = None,
        event_id: int | None = None,
        source_of_detection: str | None = None,
        confidence: float | None = None,
        evidence: Any = None,
        alert_timestamp: Any = None,
    ) -> int | None:
        """Ghi cảnh báo vào bảng alerts và trả về id.

        ``source_alert_id``/``event_id`` được giữ trong evidence để dashboard
        truy vết ngược về raw_events mà không phá vỡ schema cũ.
        """
        if not self.enabled:
            return None
        try:
            evidence_obj = dict(evidence or {})
            if event_id is not None:
                evidence_obj.setdefault("event_id", event_id)
            if source_alert_id is not None:
                evidence_obj.setdefault("source_alert_id", source_alert_id)
            evidence_json = json.dumps(evidence_obj, default=str)
            timestamp = _parse_event_timestamp(alert_timestamp) if alert_timestamp else _utc_now()
            with self._lock:
                conn = self._connect()
                cur = conn.cursor()
                cur.execute(
                    f"""
                    INSERT INTO {self.table_alerts} (
                        ts, src_ip, dest_ip, attack_type, score, severity, status,
                        alert_timestamp, source_of_detection, confidence, evidence
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s
                    )
                    RETURNING id
                    """,
                    (
                        _utc_now().isoformat(),
                        src_ip,
                        dest_ip,
                        attack_type,
                        float(score or 0.0),
                        severity,
                        status,
                        timestamp,
                        source_of_detection or "AI_Engine",
                        float(confidence if confidence is not None else score or 0.0),
                        evidence_json,
                    ),
                )
                row = cur.fetchone()
                cur.close()
                self.saved_alerts += 1
            return int(row[0]) if row else None
        except Exception as exc:
            self.last_error = str(exc)
            logger.error("Không lưu được cảnh báo cho %s: %s", src_ip, exc)
            self._drop_connection()
            return None

    # ── Truy vấn phục vụ dashboard/forensics ─────────────────────────────

    def get_event(self, event_id: int) -> dict[str, Any] | None:
        """Đọc một raw event theo id (kèm raw_json)."""
        if not self.enabled or event_id is None:
            return None
        try:
            with self._lock:
                conn = self._connect()
                cur = conn.cursor()
                cur.execute(
                    f"SELECT * FROM {self.table_logs} WHERE id = %s",
                    (event_id,),
                )
                row = cur.fetchone()
                cols = [desc[0] for desc in cur.description]
                cur.close()
            if not row:
                return None
            result = dict(zip(cols, row))
            for key, value in list(result.items()):
                if isinstance(value, datetime):
                    result[key] = value.isoformat()
            return result
        except Exception as exc:
            self.last_error = str(exc)
            self._drop_connection()
            return None

    def get_predictions_for_event(self, event_id: int) -> list[dict[str, Any]]:
        """Các dự đoán AI đã sinh cho một raw event."""
        if not self.enabled or event_id is None:
            return []
        try:
            with self._lock:
                conn = self._connect()
                cur = conn.cursor()
                cur.execute(
                    f"""
                    SELECT model_name, model_version, predicted_label, confidence,
                           risk_level, inference_timestamp, inference_latency_ms,
                           explanation
                    FROM {self.table_predictions}
                    WHERE event_id = %s
                    ORDER BY id ASC
                    """,
                    (event_id,),
                )
                rows = cur.fetchall()
                cols = [desc[0] for desc in cur.description]
                cur.close()
            result = []
            for row in rows:
                item = dict(zip(cols, row))
                if isinstance(item.get("inference_timestamp"), datetime):
                    item["inference_timestamp"] = item[
                        "inference_timestamp"
                    ].isoformat()
                result.append(item)
            return result
        except Exception as exc:
            self.last_error = str(exc)
            self._drop_connection()
            return []

    # ── Thống kê pipeline cho dashboard ──────────────────────────────────

    def get_pipeline_stats(self) -> dict[str, Any]:
        """Số liệu từng chặng: raw_events → features/predictions → alerts."""
        empty = {
            "enabled": self.enabled,
            "raw_total": 0,
            "raw_pending": 0,
            "raw_processing": 0,
            "raw_processed": 0,
            "raw_failed": 0,
            "features_total": 0,
            "predictions_total": 0,
            "alerts_total": 0,
            "last_event_at": None,
            "last_prediction_at": None,
            "last_alert_at": None,
            "last_error": self.last_error,
        }
        if not self.enabled:
            return empty
        try:
            with self._lock:
                conn = self._connect()
                cur = conn.cursor()
                cur.execute(
                    f"""
                    SELECT
                        COUNT(*) AS raw_total,
                        COUNT(*) FILTER (
                            WHERE processed = FALSE
                              AND COALESCE(processing_status, 'pending') = 'pending'
                        ) AS raw_pending,
                        COUNT(*) FILTER (WHERE processing_status = 'processing') AS raw_processing,
                        COUNT(*) FILTER (WHERE processed = TRUE) AS raw_processed,
                        COUNT(*) FILTER (WHERE processing_status = 'failed') AS raw_failed,
                        MAX(received_timestamp) AS last_event_at
                    FROM {self.table_logs}
                    """
                )
                raw = cur.fetchone()
                cur.execute(f"SELECT COUNT(*) FROM {self.table_features}")
                features_total = int(cur.fetchone()[0])
                cur.execute(
                    f"SELECT COUNT(*), MAX(inference_timestamp) FROM {self.table_predictions}"
                )
                pred_row = cur.fetchone()
                cur.execute(
                    f"SELECT COUNT(*), MAX(alert_timestamp) FROM {self.table_alerts}"
                )
                alert_row = cur.fetchone()
                cur.close()
            return {
                "enabled": True,
                "raw_total": int(raw[0] or 0),
                "raw_pending": int(raw[1] or 0),
                "raw_processing": int(raw[2] or 0),
                "raw_processed": int(raw[3] or 0),
                "raw_failed": int(raw[4] or 0),
                "last_event_at": raw[5].isoformat() if raw[5] else None,
                "features_total": features_total,
                "predictions_total": int(pred_row[0] or 0),
                "last_prediction_at": (
                    pred_row[1].isoformat() if pred_row[1] else None
                ),
                "alerts_total": int(alert_row[0] or 0),
                "last_alert_at": alert_row[1].isoformat() if alert_row[1] else None,
                "last_error": self.last_error,
            }
        except Exception as exc:
            self.last_error = str(exc)
            self._drop_connection()
            empty["last_error"] = self.last_error
            return empty

    # ── Tiện ích ─────────────────────────────────────────────────────────

    def _drop_connection(self) -> None:
        try:
            if self._conn is not None:
                self._conn.close()
        except Exception:
            pass
        self._conn = None

    def close(self) -> None:
        with self._lock:
            self._drop_connection()

    def get_status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "has_driver": HAS_PSYCOPG2,
            "host": self.host,
            "port": self.port,
            "dbname": self.dbname,
            "saved_logs": self.saved_logs,
            "duplicate_logs": self.duplicate_logs,
            "saved_alerts": self.saved_alerts,
            "saved_predictions": self.saved_predictions,
            "saved_features": self.saved_features,
            "last_error": self.last_error,
            **self.get_pipeline_stats(),
        }
