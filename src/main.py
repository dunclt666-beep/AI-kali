"""
Điểm vào chính của toàn bộ hệ thống (Main Entrypoint).
- Đọc cấu hình từ config.yaml
- Khởi tạo Database, Sliding Window Tracker, Attack Classifier, Scorer, Blocker, Alert Manager
- Chạy LogCollector thu thập log eve.json trên luồng riêng
- Chạy Worker xử lý sự kiện và tính điểm phát hiện sớm trên luồng riêng
- Khởi động Flask Dashboard trên luồng máy chủ web
- Quản lý vòng đời và dừng ứng dụng an toàn khi nhận tín hiệu kết thúc (Ctrl+C / SIGINT / SIGTERM)
Chạy bằng lệnh: python src/main.py
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os

import signal
import socket
import sys
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

# Đảm bảo Python nhận diện được thư mục gốc của dự án
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import yaml
from src.pg_store import PostgresStore

from src.alert_manager import AlertManager
from src.blocker import IPBlocker
from src.collector import LogCollector
from src.features import SlidingWindowTracker, has_sql_payload_markers, parse_timestamp
from src.pfsense_collector import PfSenseLogCollector
from src.dashboard import APP_CONTEXT, run_dashboard
from src.db import add_to_whitelist, clear_alerts, init_db, purge_expired_blocks
from src.model import AttackClassifier
from src.scorer import EarlyDetectionScorer

# Thiết lập hệ thống ghi log
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("AI_IDS.Main")


# Cổng dịch vụ phía server, dùng để suy ra đâu là server khi Suricata ghi nhầm chiều
DEFAULT_SERVER_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389,
    5432, 5900, 6379, 8000, 8008, 8080, 8443, 8888,
]

# Các công cụ dò quét / tấn công web điển hình (khớp một phần User-Agent)
SCAN_UA_HINTS = ("nmap", "gobuster", "dirbuster", "wpscan", "masscan", "nikto", "skipfish")
BRUTEFORCE_UA_HINTS = ("hydra", "medusa", "patator", "ncrack")
SQLI_UA_HINTS = ("sqlmap", "havij")

# Ngưỡng của các luật phát hiện nhanh. Có thể ghi đè trong config.yaml mục `detection`.
# Các ngưỡng này được chọn đủ chặt để KHÔNG báo nhầm lưu lượng bình thường
# (duyệt web, SSH, DNS, apt, dashboard...) nhưng vẫn bắt được công cụ tấn công thật.
DEFAULT_DETECTION: dict[str, Any] = {
    # --- Luật Flow ---
    # Quét cổng: số cổng đích khác nhau tối thiểu trong cửa sổ trượt
    "scan_unique_ports": 12,
    # Hoặc nhiều luồng ngắn nhưng vẫn trải trên nhiều cổng (quét cổng chậm)
    "scan_short_flows": 15,
    "scan_min_ports": 4,
    # DoS: tốc độ gói tối đa của một luồng (gói/giây) để coi là flood
    "dos_pps": 400.0,
    # Hoặc bùng nổ rất nhiều luồng ngắn dồn dập trong thời gian ngắn
    "dos_short_flows": 18,
    "dos_burst_seconds": 3.0,
    "dos_burst_packets": 800.0,
    # --- Luật HTTP ---
    "http_scan_ratio_4xx": 0.6,
    "http_scan_unique_urls": 10,
    "http_bruteforce_login_fails": 5,
    "http_dos_req_rate": 25.0,
    # UA công cụ chung (curl, python-requests...) chỉ được cộng điểm vừa phải,
    # tránh báo nhầm các health-check hợp lệ.
    "generic_tool_user_agents": ["curl", "python-requests"],
    "generic_tool_prob": 0.75,
    # --- Sự kiện cảnh báo Suricata ---
    # Bỏ qua chữ ký mức thấp/nhiễu (severity >= giá trị này, mặc định 3 = low).
    # Đặt 4 để tắt hoàn toàn bộ lọc.
    "suricata_min_severity": 3,
    # Bỏ qua sự kiện đã cũ hơn X giây so với hiện tại. Mục đích: khi log bị đọc
    # lại (replay) hoặc pfSense đồng bộ lại file cũ, sự kiện cũ không tạo cảnh
    # báo mới. Đặt 0 để tắt bộ lọc (cần cho chế độ phát lại log demo).
    "max_event_age_seconds": 60.0,
}


def is_stale_event(
    event: dict[str, Any],
    max_age_seconds: float,
    now_ts: float | None = None,
) -> bool:
    """True nếu sự kiện Suricata đã cũ hơn ``max_age_seconds`` giây.

    Hàm thuần này là hàng rào chống "bão cảnh báo" khi file log cũ bị phát lại:
    dù collector có đọc lại bao nhiêu lần, sự kiện cũ vẫn bị bỏ qua trước khi
    vào pipeline chấm điểm. ``max_age_seconds <= 0`` tắt bộ lọc.
    """
    if max_age_seconds is None or float(max_age_seconds) <= 0:
        return False
    ts_raw = event.get("timestamp")
    if not ts_raw:
        return False
    try:
        event_ts = parse_timestamp(ts_raw)
    except Exception:
        return False
    current_ts = time.time() if now_ts is None else float(now_ts)
    return (current_ts - event_ts) > float(max_age_seconds)



def evaluate_flow_rules(win_feat: dict[str, Any], detection: dict[str, Any]) -> str | None:
    """
    Đánh giá chuỗi sự kiện Flow của một IP. Trả về "scan"/"dos" khi hành vi rõ rệt,
    ngược lại None (không tạo cảnh báo).

    Được tách thành hàm thuần để dễ kiểm thử và tránh báo nhầm lưu lượng bình thường:
    - SCAN cần rất nhiều cổng đích khác nhau (hoặc cực nhiều luồng ngắn trải cổng).
    - DOS cần tốc độ gói/giây của MỘT luồng rất cao, hoặc bùng nổ luồng ngắn
      dồn dập với số gói lớn.
    """
    unique_ports = float(win_feat.get("unique_dst_ports", 0.0))
    short_flows = float(win_feat.get("short_flow_count", 0.0))
    peak_pps = float(win_feat.get("peak_flow_pps", 0.0))
    span = float(win_feat.get("window_span_seconds", 0.0))
    total_pkts = float(win_feat.get("window_total_pkts", 0.0))

    scan_ports = float(detection.get("scan_unique_ports", DEFAULT_DETECTION["scan_unique_ports"]))
    scan_short = float(detection.get("scan_short_flows", DEFAULT_DETECTION["scan_short_flows"]))
    scan_min_ports = float(detection.get("scan_min_ports", DEFAULT_DETECTION["scan_min_ports"]))
    dos_pps = float(detection.get("dos_pps", DEFAULT_DETECTION["dos_pps"]))
    dos_short = float(detection.get("dos_short_flows", DEFAULT_DETECTION["dos_short_flows"]))
    dos_seconds = float(detection.get("dos_burst_seconds", DEFAULT_DETECTION["dos_burst_seconds"]))
    dos_pkts = float(detection.get("dos_burst_packets", DEFAULT_DETECTION["dos_burst_packets"]))

    if unique_ports >= scan_ports or (short_flows >= scan_short and unique_ports >= scan_min_ports):
        return "scan"

    if peak_pps >= dos_pps or (short_flows >= dos_short and span <= dos_seconds and total_pkts >= dos_pkts):
        return "dos"

    return None


def evaluate_http_fasttrack(
    features: dict[str, Any],
    user_agent: str,
    url: str,
    detection: dict[str, Any],
) -> tuple[str, float] | None:
    """
    Luật fast-track cho HTTP: chỉ trả về (loại tấn công, xác suất) khi có bằng chứng
    rõ ràng (User-Agent công cụ, payload SQL thật, dò đường dẫn, brute-force, DoS).
    """
    ua_low = (user_agent or "").lower()

    sql_kw = float(features.get("sql_keyword_count", 0.0))
    special = float(features.get("special_char_count", 0.0))
    login_fail = float(features.get("login_fail_count", 0.0))
    ratio_4xx = float(features.get("ratio_4xx", 0.0))
    unique_urls = float(features.get("unique_urls", 0.0))
    req_rate = float(features.get("req_rate", 0.0))
    peak_pps = float(features.get("peak_flow_pps", 0.0))
    http_count = float(features.get("window_http_count", 0.0))

    # 1. SQL Injection
    if any(hint in ua_low for hint in SQLI_UA_HINTS):
        return "sqli", 0.98
    if sql_kw >= 2.0 and special >= 3.0:
        return "sqli", 0.98
    if sql_kw >= 1.0 and special >= 3.0 and has_sql_payload_markers(url):
        return "sqli", 0.98

    # 2. Dò quét đường dẫn / file (404 hàng loạt)
    if any(hint in ua_low for hint in SCAN_UA_HINTS):
        return "scan", 0.95
    scan_ratio = float(detection.get("http_scan_ratio_4xx", DEFAULT_DETECTION["http_scan_ratio_4xx"]))
    scan_urls = float(detection.get("http_scan_unique_urls", DEFAULT_DETECTION["http_scan_unique_urls"]))
    if ratio_4xx >= scan_ratio and unique_urls >= scan_urls:
        return "scan", 0.95

    # 3. Brute-force đăng nhập
    if any(hint in ua_low for hint in BRUTEFORCE_UA_HINTS):
        return "bruteforce", 0.95
    brute_fails = float(
        detection.get("http_bruteforce_login_fails", DEFAULT_DETECTION["http_bruteforce_login_fails"])
    )
    if login_fail >= brute_fails:
        return "bruteforce", 0.95

    # 4. DoS tầng ứng dụng
    dos_rate = float(detection.get("http_dos_req_rate", DEFAULT_DETECTION["http_dos_req_rate"]))
    dos_pps = float(detection.get("dos_pps", DEFAULT_DETECTION["dos_pps"]))
    if (req_rate >= dos_rate and http_count >= 5.0) or peak_pps >= dos_pps:
        return "dos", 0.96

    return None


class SystemManager:
    """Điều phối toàn bộ các thành phần trong hệ thống AI IDS."""

    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = self.load_config(config_path)
        self.running = threading.Event()
        # self.event_queue removed; using DB-based event claims

        # Mốc bắt đầu phiên chạy: dashboard chỉ hiển thị cảnh báo phát sinh từ
        # mốc này trở đi, không hiện lại cảnh báo cũ đã lưu trong PostgreSQL.
        self.session_started_at = datetime.now().isoformat()
        APP_CONTEXT["session_started_at"] = self.session_started_at

        # 1. Khởi tạo PostgreSQL
        init_db(self.config.get("database", {}))

        # Tuỳ chọn: xoá cảnh báo cũ ngay khi khởi động (mặc định tắt).
        alert_cfg = self.config.get("alert", {}) or {}
        if bool(alert_cfg.get("clear_on_start", False)):
            try:
                removed = clear_alerts()
                logger.info("Đã xoá %d cảnh báo cũ trong PostgreSQL khi khởi động.", removed)
            except Exception as ex:
                logger.error("Không xoá được cảnh báo cũ khi khởi động: %s", ex)

        # Nạp IP whitelist ban đầu vào DB
        for w_ip in self.config.get("whitelist_ips", []):
            add_to_whitelist(w_ip, "Cấu hình ban đầu từ config.yaml")

        # 2. Khởi tạo Cửa sổ trượt (Sliding Window Tracker)
        sw_cfg = self.config.get("sliding_window", {})
        self.window_tracker = SlidingWindowTracker(
            window_size_n=int(sw_cfg.get("window_size_n", 20)),
            window_time_t=float(sw_cfg.get("window_time_t", 60.0)),
        )

        # 3. Khởi tạo Mô hình AI (Ensemble RF + LSTM, tương thích cả config cũ)
        m_cfg = self.config.get("model", {})
        self.classifier = AttackClassifier(
            rf_model_path=m_cfg.get("rf_model_path", m_cfg.get("model_path", "models/detector_model.joblib")),
            lstm_model_path=m_cfg.get("lstm_model_path", "models/lstm_model.joblib"),
            weight_rf=float(m_cfg.get("weight_rf", 0.5)),
            weight_lstm=float(m_cfg.get("weight_lstm", 0.5)),
            seq_len=int(m_cfg.get("seq_len", 5)),
        )

        # 4. Khởi tạo Bộ tính điểm phát hiện sớm (EMA Scorer)
        s_cfg = self.config.get("scoring", {})
        self.scorer = EarlyDetectionScorer(
            alpha=float(s_cfg.get("alpha", 0.4)),
            theta=float(s_cfg.get("theta", 0.6)),
            high_threshold=float(s_cfg.get("high_threshold", 0.85)),
            fast_detection=bool(s_cfg.get("fast_detection", True)),
        )

        # 4b. Cấu hình nhận diện IP tấn công (Suricata có thể ghi src_ip là phía server)
        n_cfg = self.config.get("network", {})
        self.attacker_selection = str(n_cfg.get("attacker_selection", "auto")).lower()
        self.server_ips = {str(ip) for ip in (n_cfg.get("server_ips") or [])}
        self.server_ports = {
            int(p) for p in (n_cfg.get("server_ports") or DEFAULT_SERVER_PORTS)
        }
        self.protected_networks: list[Any] = []
        for net in (n_cfg.get("protected_networks") or []):
            try:
                self.protected_networks.append(ipaddress.ip_network(str(net), strict=False))
            except ValueError:
                logger.warning("Dải mạng không hợp lệ trong network.protected_networks: %s", net)

        # Các IP của chính máy đang chạy IDS cũng được coi là phía server.
        # Nhờ vậy lưu lượng hợp lệ của máy web server không bao giờ bị gán nhãn "kẻ tấn công".
        self.protect_local_ips = bool(n_cfg.get("protect_local_ips", True))
        self.local_ips = self._detect_local_ips() if self.protect_local_ips else set()
        if self.local_ips:
            logger.info("Bảo vệ các IP cục bộ (không coi là kẻ tấn công): %s", ", ".join(sorted(self.local_ips)))

        # 4c. Ngưỡng luật phát hiện nhanh (có thể ghi đè trong config.yaml mục `detection`)
        self.detection: dict[str, Any] = dict(DEFAULT_DETECTION)
        self.detection.update({
            key: value
            for key, value in (self.config.get("detection") or {}).items()
            if value is not None
        })
        self.generic_tool_uas = tuple(
            str(ua).lower()
            for ua in (self.detection.get("generic_tool_user_agents") or [])
        )
        # Ngưỡng chống phát lại log cũ: sự kiện cũ hơn ngưỡng này bị bỏ qua
        # trước khi vào pipeline chấm điểm (0 = tắt).
        self.max_event_age_seconds = float(
            self.detection.get("max_event_age_seconds", 60.0)
        )

        # 5. Khởi tạo Bộ chặn tường lửa (IP Blocker)
        b_cfg = self.config.get("blocking", {})
        self.blocker = IPBlocker(
            block_cmd_prefix=b_cfg.get("ufw_block_command", "sudo ufw insert 1 deny from"),
            unblock_cmd_prefix=b_cfg.get("ufw_unblock_command", "sudo ufw delete deny from"),
            default_duration_minutes=int(b_cfg.get("default_duration_minutes", 60)),
        )

        # 6. Khởi tạo Bộ quản lý cảnh báo (Alert Manager)
        a_cfg = self.config.get("alert", {})
        self.alert_manager = AlertManager(
            scorer=self.scorer,
            blocker=self.blocker,
            countdown_seconds=int(a_cfg.get("countdown_seconds", 5)),
            auto_block_enabled=bool(a_cfg.get("auto_block_enabled", True)),
            cooldown_seconds=int(a_cfg.get("cooldown_seconds", 30)),
        )

        # 7. pfSense truoc de tu dong doi log.path sang file pfSense khi bat
        self.pfsense_collector = None
        self._init_pfsense_collector()

        # 8. LogCollector doc eve.json (uu tien file pfSense)
        log_cfg = self.config.get("log", {})
        log_path = log_cfg.get("path", "data/sample_eve.json")
        if self.pfsense_collector is not None:
            pf_local = str(self.pfsense_collector.local_path)
            log_path = pf_local
            self.config.setdefault("log", {})["path"] = pf_local
        self.pg_store = PostgresStore(self.config.get('database', {}))
        if not self.pg_store.init_schema():
            logger.error("Failed to initialize PostgreSQL schema: %s", self.pg_store.last_error)
        self.collector = LogCollector(
            log_path=log_path,
            pg_store=self.pg_store,
            poll_interval=float(log_cfg.get("poll_interval", 0.2)),
            start_at_end=bool(log_cfg.get("start_at_end", True)),
        )

        # 8b. Tham số của Worker AI (batch + nhịp poll)
        w_cfg = self.config.get("worker", {}) or {}
        self.worker_batch_size = max(1, int(w_cfg.get("batch_size", 20)))
        self.worker_poll_interval = max(
            0.05, float(w_cfg.get("poll_interval", 0.2))
        )

        # 9. Danh sach ho tro trich dac trung + thread worker/dashboard
        self.login_paths = self.config.get("paths", {}).get("login_paths", [])
        self.attack_user_agents = self.config.get("attack_user_agents", [])
        self.worker_thread = threading.Thread(
            target=self._process_events_worker, name="EventWorkerThread", daemon=True
        )
        self.dashboard_thread = None
        self._last_purge = 0.0
        # Dọn trạng thái định kỳ ngắn để IP đã ngừng tấn công được reset sớm,
        # không giữ điểm EMA cao gây cảnh báo "dư".
        self._purge_interval = float(
            (self.config.get("alert", {}) or {}).get("maintenance_interval_seconds", 10.0)
        )
        # Bộ nhớ đệm chống xử lý trùng lặp sự kiện (ví dụ khi log bị đọc lại/replay)
        self._recent_event_keys: deque[tuple] = deque(maxlen=5000)
        self._recent_event_key_set: set[tuple] = set()

    def _init_pfsense_collector(self) -> None:
        """Khởi tạo PfSenseLogCollector từ cấu hình"""
        pfsense_cfg = self.config.get("pfsense", {})
        if pfsense_cfg.get("enabled", False):
            self.pfsense_collector = PfSenseLogCollector(pfsense_cfg)
            logger.info("Đã khởi tạo PfSenseLogCollector (tích hợp vào SystemManager)")
        else:
            logger.info("pfSense collector đang TẮT (enabled=false)")

    def start(self) -> None:
        """Khởi động toàn bộ luồng hoạt động của hệ thống"""
        self.running.set()
        logger.info("=" * 60)
        logger.info("   HỆ THỐNG AI PHÁT HIỆN SỚM TẤN CÔNG WEB SERVER ĐANG KHỞI CHẠY   ")
        logger.info("=" * 60)

        # 1. Bật luồng đọc log Suricata
        self.collector.start()

        # 2. Bật luồng thu thập log từ pfSense (nếu cấu hình)
        if self.pfsense_collector:
            self.pfsense_collector.start()
            logger.info("Bắt đầu luồng thu thập log từ pfSense")

        # 3. Bật luồng phân tích đặc trưng và chấm điểm
        self.worker_thread.start()

        # 4. Bật luồng Flask Dashboard
        d_cfg = self.config.get("dashboard", {})
        host = d_cfg.get("host", "0.0.0.0")
        port = int(d_cfg.get("port", 5000))
        debug = bool(d_cfg.get("debug", False))

        self.dashboard_thread = threading.Thread(
            target=run_dashboard,
            args=(host, port, debug),
            name="DashboardThread",
            daemon=True,
        )
        self.dashboard_thread.start()

        logger.info("Dashboard sẵn sàng tại: http://%s:%d", host, port)

        # Cung cấp tham chiếu trạng thái cho Flask Dashboard
        APP_CONTEXT.update({
            "collector": self.collector,
            "model": self.classifier,
            "scorer": self.scorer,
            "blocker": self.blocker,
            "alert_manager": self.alert_manager,
            "window_tracker": self.window_tracker,
            "config": self.config,
            "config_path": self.config_path,
            "pfsense_collector": self.pfsense_collector,
            "pg_store": self.pg_store,
            "worker_batch_size": self.worker_batch_size,
            "session_started_at": self.session_started_at,
        })

    @staticmethod
    def load_config(path: str) -> dict[str, Any]:
        """Đọc tệp cấu hình YAML."""
        if not os.path.exists(path):
            logger.warning("Không tìm thấy %s, sử dụng cấu hình mặc định.", path)
            return {}
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def _run_periodic_maintenance(self) -> None:
        """Định kỳ: gỡ chặn IP hết hạn và xoá trạng thái của các IP đã ngừng hoạt động."""
        now = time.time()
        if now - self._last_purge < self._purge_interval:
            return
        self._last_purge = now

        # 1. Gỡ chặn các IP đã hết thời hạn
        try:
            expired_ips = purge_expired_blocks()
        except Exception as ex:
            logger.error("Lỗi dọn dẹp IP hết hạn chặn: %s", ex)
            expired_ips = []
        for ip in expired_ips:
            logger.info("IP %s đã hết thời hạn chặn, tiến hành gỡ chặn.", ip)
            try:
                if self.blocker is not None:
                    self.blocker.unblock_ip(ip)
            except Exception as ex:
                logger.error("Không gỡ được chặn cho IP %s: %s", ip, ex)

        # 2. Xoá cửa sổ trượt + điểm tích lũy của các IP đã ngừng gửi sự kiện,
        #    tránh việc tiếp tục cảnh báo sau khi cuộc tấn công đã dừng.
        try:
            idle_reset = float(
                (self.config.get("scoring", {}) or {}).get("idle_reset_seconds", 0) or 0
            )
            idle_seconds = (
                idle_reset
                if idle_reset > 0
                else max(float(self.window_tracker.window_time_t), 1.0)
            )
            idle_ips = self.window_tracker.idle_ips(now, idle_seconds)
        except Exception as ex:
            logger.error("Lỗi kiểm tra IP không hoạt động: %s", ex)
            idle_ips = []

        for ip in idle_ips:
            self.window_tracker.reset_ip(ip)
            self.scorer.reset_score(ip)
        if idle_ips:
            logger.info(
                "Đã xoá trạng thái cửa sổ của %d IP đã ngừng hoạt động.", len(idle_ips)
            )

    @staticmethod
    def _event_fingerprint(event: dict[str, Any]) -> tuple:
        """Khoá nhận diện sự kiện để phát hiện log bị phát lại (replay)."""
        alert_obj = event.get("alert") or {}
        return (
            event.get("event_type"),
            event.get("src_ip"),
            event.get("timestamp"),
            event.get("dest_port"),
            alert_obj.get("signature"),
        )

    def _is_duplicate_event(self, event: dict[str, Any]) -> bool:
        """True nếu sự kiện đã được xử lý gần đây (tránh cảnh báo lặp do replay log)."""
        key = self._event_fingerprint(event)
        if key in self._recent_event_key_set:
            return True
        if len(self._recent_event_keys) == self._recent_event_keys.maxlen:
            self._recent_event_key_set.discard(self._recent_event_keys[0])
        self._recent_event_keys.append(key)
        self._recent_event_key_set.add(key)
        return False

    @staticmethod
    def _detect_local_ips() -> set[str]:
        """Các IP của chính máy đang chạy IDS (loopback + IP LAN đang dùng)."""
        ips: set[str] = {"127.0.0.1", "::1"}
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None):
                addr = info[4][0]
                if addr:
                    ips.add(str(addr))
        except Exception:
            pass
        # Không gửi gói tin nào, chỉ hỏi hệ điều hành IP của tuyến mặc định
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.2)
                sock.connect(("8.8.8.8", 80))
                ips.add(str(sock.getsockname()[0]))
        except Exception:
            pass
        return ips

    def _is_server_side(self, ip: str | None) -> bool:
        """True nếu IP thuộc phía server theo cấu hình (server_ips / protected_networks)."""
        if not ip:
            return False
        if ip in self.server_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.protected_networks)

    def _is_protected_ip(self, ip: str | None) -> bool:
        """
        True nếu IP là phía server: cấu hình trong network.server_ips /
        network.protected_networks, hoặc là IP của chính máy chạy IDS
        (khi network.protect_local_ips=true). Các IP này không bao giờ bị coi
        là kẻ tấn công.
        """
        if self._is_server_side(ip):
            return True
        if self.protect_local_ips and ip and ip in self.local_ips:
            return True
        return False

    def _resolve_attacker_ip(self, event: dict[str, Any]) -> str | None:
        """
        Xác định IP tấn công thật của sự kiện.

        Trên một số cấu hình (pfSense/Suricata theo dõi chiều phản hồi), trường ``src_ip``
        lại chính là IP web server, còn IP kẻ tấn công nằm ở ``dest_ip``. Hàm này chọn
        đúng phía client để không báo nhầm IP nạn nhân.

        Trả về ``None`` khi sự kiện do chính phía server khởi tạo (không phải tấn công).
        """
        src = event.get("src_ip")
        dst = event.get("dest_ip")
        if not src:
            return None
        if self.attacker_selection == "src" or not dst or src == dst:
            return src

        # 1. Suy luận theo cổng: phía client dùng cổng tạm, phía server dùng cổng dịch vụ
        try:
            src_port = int(event["src_port"]) if event.get("src_port") is not None else None
        except (TypeError, ValueError):
            src_port = None
        try:
            dst_port = int(event["dest_port"]) if event.get("dest_port") is not None else None
        except (TypeError, ValueError):
            dst_port = None
        src_is_svc = src_port in self.server_ports if src_port is not None else False
        dst_is_svc = dst_port in self.server_ports if dst_port is not None else False
        if dst_is_svc != src_is_svc:
            # Chỉ một phía là server -> phía còn lại là client (nghi vấn kẻ tấn công)
            return src if dst_is_svc else dst

        # 2. Không rõ theo cổng: dùng danh sách/dải mạng server đã cấu hình
        if self._is_server_side(dst) and not self._is_server_side(src):
            return src
        if self._is_server_side(src) and not self._is_server_side(dst):
            # Lưu lượng do server tự khởi tạo, không phải kẻ tấn công
            return None

        # 3. Mặc định giữ nguyên src_ip
        return src

    def _process_events_worker(self) -> None:
        """Vòng lặp Worker AI: claim raw_events từ PostgreSQL và xử lý từng sự kiện.

        Mỗi sự kiện được claim theo cơ chế lease (an toàn khi có nhiều worker).
        Sau khi xử lý xong, trạng thái được cập nhật thành ``processed`` hoặc trả
        lại queue (``pending``) kèm backoff nếu lỗi.
        """
        logger.info(
            "Luồng EventWorkerThread đã bắt đầu (batch=%d, poll=%.2fs).",
            self.worker_batch_size,
            self.worker_poll_interval,
        )

        while self.running.is_set():
            try:
                self._run_periodic_maintenance()
            except Exception as ex:
                logger.error("Lỗi bảo trì định kỳ: %s", ex)

            rows = self.pg_store.claim_pending(limit=self.worker_batch_size)
            if not rows:
                time.sleep(self.worker_poll_interval)
                continue

            for row in rows:
                if not self.running.is_set():
                    break
                self._process_claimed_row(row)

            # Nếu batch vừa xử lý đã đầy, lập tức lấy batch tiếp theo.
            if len(rows) < self.worker_batch_size:
                time.sleep(self.worker_poll_interval)

        logger.info("EventWorkerThread đã dừng.")

    def _process_claimed_row(self, row: dict[str, Any]) -> None:
        """Xử lý một bản ghi đã claim và luôn cập nhật trạng thái cuối cùng."""
        event_id = row.get("id")
        try:
            event = row.get("raw_json")
            if isinstance(event, str):
                event = json.loads(event)
            if not isinstance(event, dict):
                event = {}

            # raw_json chứa nguyên bản EVE; bổ sung các cột chuẩn hóa nếu thiếu.
            event.setdefault("event_type", row.get("event_type"))
            event.setdefault("src_ip", row.get("src_ip"))
            event.setdefault("src_port", row.get("src_port"))
            event.setdefault("dest_ip", row.get("dest_ip"))
            event.setdefault("dest_port", row.get("dest_port"))
            # Giữ id bản ghi PostgreSQL để gắn vào hồ sơ bằng chứng của alert.
            event["_db_event_id"] = event_id

            self._process_one_event(row, event)
        except Exception as ex:
            attempts = int(row.get("processing_attempts") or 1)
            logger.error(
                "Lỗi xử lý sự kiện #%s (lần %d): %s",
                event_id,
                attempts,
                ex,
                exc_info=True,
            )
            if attempts >= 3:
                # Sự kiện hỏng: đánh dấu failed để không chặn queue.
                self.pg_store.set_processing_status(
                    event_id, "failed", error_msg=str(ex)[:1000]
                )
            else:
                retry_at = datetime.now() + timedelta(
                    seconds=min(30, 2 ** attempts)
                )
                self.pg_store.set_processing_status(
                    event_id,
                    "pending",
                    error_msg=str(ex)[:1000],
                    next_retry_at=retry_at,
                )
                # Backoff nhỏ để không quay cuồng khi PostgreSQL/AI tạm lỗi.
                time.sleep(0.2 * attempts)
            return

        # Xử lý thành công (kể cả sự kiện bị bỏ qua có chủ đích).
        self.pg_store.set_processing_status(event_id, "processed")

    def _process_one_event(self, row: dict[str, Any], event: dict[str, Any]) -> None:
        """Chạy pipeline phát hiện cho một sự kiện EVE đã nằm trong PostgreSQL."""
        # Chống phát lại log cũ: sự kiện quá cũ bị bỏ qua nhưng vẫn được đánh
        # dấu processed để không quay lại queue.
        if is_stale_event(event, self.max_event_age_seconds):
            logger.debug(
                "Bỏ qua sự kiện cũ (timestamp=%s, quá %.0fs): %s",
                event.get("timestamp"),
                self.max_event_age_seconds,
                event.get("event_type"),
            )
            return

        if self._is_duplicate_event(event):
            logger.debug(
                "Bỏ qua sự kiện trùng lặp (replay log): %s",
                self._event_fingerprint(event),
            )
            return

        event_type = event.get("event_type")
        src_ip = event.get("src_ip")
        if not src_ip:
            return

        # Xác định IP tấn công thật (tránh báo nhầm IP server khi Suricata ghi
        # src_ip là phía server).
        attacker_ip = self._resolve_attacker_ip(event)
        if attacker_ip is None:
            logger.debug(
                "Bỏ qua sự kiện %s do phía server tự khởi tạo (src_ip=%s, dest_ip=%s).",
                event_type,
                src_ip,
                event.get("dest_ip"),
            )
            return
        if attacker_ip != src_ip:
            logger.debug(
                "Sự kiện %s: src_ip=%s là phía server, dùng IP tấn công=%s",
                event_type,
                src_ip,
                attacker_ip,
            )
            event["src_ip"] = attacker_ip
            src_ip = attacker_ip

        # Không bao giờ coi phía server / IP của chính máy IDS là kẻ tấn công.
        if self._is_protected_ip(src_ip):
            logger.debug(
                "Bỏ qua sự kiện %s từ IP phía server %s.",
                event_type,
                src_ip,
            )
            return

        event_id = row.get("id")

        # 1. Alert của Suricata -------------------------------------------------
        if event_type == "alert":
            alert_obj = event.get("alert", {}) or {}
            sig = str(alert_obj.get("signature", "")).lower()
            try:
                sig_severity = int(alert_obj.get("severity", 3))
            except (TypeError, ValueError):
                sig_severity = 3

            # Bỏ qua chữ ký mức thấp/nhiễu.
            if sig_severity >= int(self.detection.get("suricata_min_severity", 3)):
                logger.debug(
                    "Bỏ qua cảnh báo Suricata mức thấp (severity=%s): %s",
                    sig_severity,
                    sig,
                )
                return

            self.window_tracker.add_event(event, self.login_paths)
            features = self.window_tracker.extract_window_features(src_ip)

            if any(k in sig for k in ("sql", "sqli", "injection")):
                att = "sqli"
            elif any(k in sig for k in ("scan", "nmap", "portscan", "sweep")):
                att = "scan"
            elif any(k in sig for k in ("brute", "login", "hydra", "auth")):
                att = "bruteforce"
            elif any(k in sig for k in ("dos", "ddos", "flood")):
                att = "dos"
            else:
                att = "anomaly"

            p_t = 0.98 if sig_severity <= 1 else 0.9
            current_score, severity, is_alert = self.scorer.update_score(
                src_ip=src_ip, p_t=p_t
            )

            self.pg_store.save_features(event_id, event, features)
            self._persist_prediction(
                event_id=event_id,
                model_name="suricata_signature",
                predicted_label=att,
                confidence=p_t,
                severity=severity,
                explanation={"signature": alert_obj.get("signature")},
            )

            if is_alert and severity:
                self._emit_alert(
                    src_ip=src_ip,
                    dest_ip=event.get("dest_ip"),
                    attack_type=att,
                    score=current_score,
                    severity=severity,
                    source="Suricata_Signature",
                    confidence=p_t,
                    event=event,
                    features=features,
                )
            return

        # 2. Flow: phát hiện Port Scan / DoS -----------------------------------
        if event_type == "flow":
            self.window_tracker.add_event(event, self.login_paths)
            win_feat = self.window_tracker.extract_window_features(src_ip)
            self.pg_store.save_features(event_id, event, win_feat)

            flow_attack = evaluate_flow_rules(win_feat, self.detection)
            if not flow_attack:
                return

            p_t = 0.95 if flow_attack == "scan" else 0.96
            logger.info(
                "Luật Flow phát hiện %s: IP=%s | ports=%s short=%s peak_pps=%.1f",
                flow_attack.upper(),
                src_ip,
                win_feat.get("unique_dst_ports"),
                win_feat.get("short_flow_count"),
                win_feat.get("peak_flow_pps", 0.0),
            )
            current_score, severity, is_alert = self.scorer.update_score(
                src_ip=src_ip, p_t=p_t
            )
            self._persist_prediction(
                event_id=event_id,
                model_name="flow_rule",
                predicted_label=flow_attack,
                confidence=p_t,
                severity=severity,
                explanation={
                    "unique_dst_ports": win_feat.get("unique_dst_ports"),
                    "short_flow_count": win_feat.get("short_flow_count"),
                    "peak_flow_pps": win_feat.get("peak_flow_pps"),
                },
            )
            if is_alert and severity:
                self._emit_alert(
                    src_ip=src_ip,
                    dest_ip=event.get("dest_ip"),
                    attack_type=flow_attack,
                    score=current_score,
                    severity=severity,
                    source="Flow_Rule",
                    confidence=p_t,
                    event=event,
                    features=win_feat,
                )
            return

        # 3. HTTP: suy luận bằng Ensemble RF + LSTM ---------------------------
        if event_type == "http":
            features = self.window_tracker.get_full_feature_vector(
                http_event=event,
                login_paths=self.login_paths,
                attack_user_agents=self.attack_user_agents,
            )

            seq_input = self.window_tracker.get_feature_sequence(src_ip, seq_len=5)
            started = time.perf_counter()
            predicted_class, class_probs, attack_prob = self.classifier.predict(
                features, sequence_input=seq_input
            )
            latency_ms = (time.perf_counter() - started) * 1000.0

            http_obj = event.get("http", {}) or {}
            ua_str = str(http_obj.get("http_user_agent", "")).lower()
            raw_url = str(http_obj.get("url", "") or "")

            # Fast-track: bằng chứng rõ ràng (UA công cụ, payload SQL, brute-force...).
            fast_result = evaluate_http_fasttrack(
                features, ua_str, raw_url, self.detection
            )
            if fast_result:
                predicted_class, attack_prob = fast_result
                logger.info(
                    "Luật HTTP fast-track phát hiện %s: IP=%s | UA=%s | URL=%s",
                    predicted_class.upper(),
                    src_ip,
                    ua_str[:80] or "-",
                    raw_url[:120] or "-",
                )
            elif features.get("user_agent_flag", 0.0) > 0.0:
                if any(generic in ua_str for generic in self.generic_tool_uas):
                    attack_prob = max(
                        attack_prob,
                        float(self.detection.get("generic_tool_prob", 0.75)),
                    )
                else:
                    attack_prob = max(attack_prob, 0.92)

            current_score, severity, is_alert = self.scorer.update_score(
                src_ip=src_ip,
                p_t=attack_prob,
            )

            self.pg_store.save_features(event_id, event, features)

            source = self._detection_source(fast_result is not None)
            self._persist_prediction(
                event_id=event_id,
                model_name="ensemble",
                predicted_label=predicted_class,
                confidence=attack_prob,
                severity=severity,
                latency_ms=latency_ms,
                explanation={
                    "probabilities": class_probs,
                    "fast_track": bool(fast_result),
                    "url": raw_url[:500],
                    "user_agent": ua_str[:200],
                    "attack_probability": attack_prob,
                    "score": current_score,
                },
            )

            if is_alert and severity:
                attack_type = (
                    predicted_class if predicted_class != "normal" else "anomaly"
                )
                self._emit_alert(
                    src_ip=src_ip,
                    dest_ip=event.get("dest_ip"),
                    attack_type=attack_type,
                    score=current_score,
                    severity=severity,
                    source=source,
                    confidence=attack_prob,
                    event=event,
                    features=features,
                    class_probs=class_probs,
                )
            return

        # Các loại khác (dns/tls/...) chỉ lưu raw_events, không chấm điểm.
        logger.debug("Bỏ qua chấm điểm cho event_type=%s", event_type)

    def _detection_source(self, fast_track: bool) -> str:
        """Mô tả nguồn phát hiện để dashboard hiển thị."""
        if fast_track:
            return "AI_FastTrack"
        rf_loaded = bool(getattr(self.classifier, "is_rf_loaded", False))
        lstm_loaded = bool(getattr(self.classifier, "is_lstm_loaded", False))
        if rf_loaded and lstm_loaded:
            return "AI_Ensemble"
        if rf_loaded:
            return "AI_RandomForest"
        if lstm_loaded:
            return "AI_LSTM"
        return "AI_Heuristic"

    @staticmethod
    def _risk_level(severity: str | None, confidence: float) -> str:
        """Chuẩn hóa mức rủi ro sang INFO/LOW/MEDIUM/HIGH/CRITICAL."""
        if severity == "Cao":
            return "CRITICAL" if confidence >= 0.95 else "HIGH"
        if severity == "Trung bình":
            return "MEDIUM"
        if confidence >= 0.85:
            return "HIGH"
        if confidence >= 0.60:
            return "MEDIUM"
        if confidence >= 0.30:
            return "LOW"
        return "INFO"

    def _persist_prediction(
        self,
        event_id: int,
        model_name: str,
        predicted_label: str,
        confidence: float,
        severity: str | None,
        latency_ms: float | None = None,
        explanation: Any = None,
    ) -> None:
        """Ghi kết quả của worker AI vào bảng ai_predictions."""
        self.pg_store.save_prediction(
            event_id=event_id,
            model_name=model_name,
            model_version="1.0.0",
            predicted_label=predicted_label or "normal",
            confidence=float(confidence or 0.0),
            risk_level=self._risk_level(severity, float(confidence or 0.0)),
            inference_latency_ms=latency_ms or 0.0,
            explanation=explanation or {},
            feature_schema_version="v1.0",
        )

    def _build_evidence(
        self,
        event: dict[str, Any],
        source: str,
        features: dict[str, Any] | None = None,
        class_probs: Any = None,
    ) -> dict[str, Any]:
        """Hồ sơ bằng chứng lưu kèm alert để dashboard/forensics đọc lại."""
        http_obj = event.get("http", {}) or {}
        alert_obj = event.get("alert", {}) or {}
        features = features or {}
        return {
            "event_id": event.get("_db_event_id"),
            "suricata": {
                "signature": alert_obj.get("signature") or event.get("signature"),
                "category": alert_obj.get("category") or event.get("category"),
                "severity": alert_obj.get("severity") or event.get("severity"),
            },
            "detection_source": source,
            "ai_models": {"probabilities": class_probs or {}},
            "web_indicators": {
                "http_method": http_obj.get("http_method"),
                "url": http_obj.get("url"),
                "status": http_obj.get("status"),
                "user_agent": http_obj.get("http_user_agent"),
                "hostname": http_obj.get("hostname"),
            },
            "features_summary": {
                "unique_dst_ports": features.get("unique_dst_ports"),
                "short_flow_count": features.get("short_flow_count"),
                "peak_flow_pps": features.get("peak_flow_pps"),
                "req_rate": features.get("req_rate"),
                "ratio_4xx": features.get("ratio_4xx"),
                "failed_login_count": features.get("login_fail_count"),
                "sql_keyword_count": features.get("sql_keyword_count"),
                "special_char_count": features.get("special_char_count"),
            },
            "event": {
                "flow_id": event.get("flow_id"),
                "timestamp": event.get("timestamp"),
                "src_ip": event.get("src_ip"),
                "src_port": event.get("src_port"),
                "dest_ip": event.get("dest_ip"),
                "dest_port": event.get("dest_port"),
                "proto": event.get("proto"),
            },
        }

    def _emit_alert(
        self,
        src_ip: str,
        dest_ip: str | None,
        attack_type: str,
        score: float,
        severity: str,
        source: str,
        confidence: float,
        event: dict[str, Any],
        features: dict[str, Any] | None = None,
        class_probs: Any = None,
    ) -> int | None:
        """Tạo cảnh báo qua AlertManager (whitelist/cooldown/DB/đếm ngược)."""
        evidence = self._build_evidence(event, source, features, class_probs)
        try:
            alert_id = self.alert_manager.process_score(
                src_ip=src_ip,
                attack_type=attack_type,
                score=score,
                severity=severity,
                dest_ip=dest_ip,
                source_of_detection=source,
                confidence=confidence,
                evidence=evidence,
            )
        except Exception as ex:
            logger.error("Không tạo được cảnh báo cho %s: %s", src_ip, ex)
            return None
        if alert_id:
            logger.warning(
                "CẢNH BÁO #%s [%s] IP=%s loại=%s nguồn=%s điểm=%.3f",
                alert_id,
                severity,
                src_ip,
                attack_type,
                source,
                score,
            )
        return alert_id

    def stop(self) -> None:
        """Dừng tất cả các thành phần an toàn."""
        logger.info("Đang dừng hệ thống AI IDS...")
        self.running.clear()
        
        if self.collector:
            self.collector.stop()
        
        # Dừng bộ thu thập log từ pfSense
        if self.pfsense_collector:
            self.pfsense_collector.stop()

        # Đóng kết nối PostgreSQL sau khi các luồng đã dừng.
        try:
            if self.worker_thread.is_alive():
                self.worker_thread.join(timeout=5)
        except Exception:
            pass
        try:
            self.pg_store.close()
        except Exception:
            pass

        logger.info("Hệ thống đã dừng hoàn toàn.")


def main():
    parser = argparse.ArgumentParser(description="AI Early Web Attack Detection System")
    parser.add_argument("--config", default="config.yaml", help="Đường dẫn tệp cấu hình YAML")
    args = parser.parse_args()

    manager = SystemManager(config_path=args.config)
    manager.start()

    def handle_signal(sig, frame):
        logger.info("Nhận tín hiệu ngắt (%s). Đang tắt ứng dụng...", sig)
        manager.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Giữ luồng chính luôn chạy
    try:
        while manager.running.is_set():
            time.sleep(1.0)
    except KeyboardInterrupt:
        manager.stop()


if __name__ == "__main__":
    main()
