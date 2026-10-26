"""
Module trích xuất đặc trưng cho hệ thống AI phát hiện sớm tấn công web server.
Trích xuất đặc trưng mức Request (HTTP) và mức Cửa sổ trượt (HTTP, Flow, Alert) cho từng IP nguồn.
"""

from __future__ import annotations

import math
import re
import threading
from collections import Counter, deque
from datetime import datetime
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

# Danh sách đầy đủ 19 đặc trưng được đưa vào mô hình AI
FEATURE_COLUMNS: list[str] = [
    # Mức request (HTTP)
    "url_length",
    "special_char_count",
    "sql_keyword_count",
    "param_entropy",
    "method_is_post",
    "status",
    "is_login_path",
    "user_agent_flag",
    # Mức cửa sổ - HTTP
    "req_rate",
    "unique_urls",
    "ratio_4xx",
    "login_fail_count",
    "inter_request_time",
    # Mức cửa sổ - Flow
    "unique_dst_ports",
    "short_flow_count",
    "pkts_per_sec",
    "bytes_per_sec",
    "concurrent_flows",
    # Mức cửa sổ - Alert
    "suricata_alert_count",
]

# Tập các ký tự đặc biệt cần đếm: ' " ; < > ( ) = -
SPECIAL_CHARS = set("'\"<>()=-;")

# Danh sách từ khóa SQL injection (case-insensitive)
SQL_KEYWORDS = [
    "select",
    "union",
    "insert",
    "update",
    "delete",
    "drop",
    "sleep",
    "benchmark",
    "'or 1=1'",
    "--",
    "xp_cmdshell",
    "information_schema",
]

# Dấu hiệu payload đặc trưng của SQL Injection. Các từ khóa như "delete"/"update"
# hoàn toàn có thể xuất hiện trên URL hợp lệ (/delete.php?id=3), vì vậy chỉ coi là
# tấn công khi từ khóa đi kèm một trong các dấu hiệu payload dưới đây.
SQL_PAYLOAD_MARKERS = (
    "'",
    '"',
    "--",
    "/*",
    " or ",
    "union",
    "sleep(",
    "benchmark(",
    "waitfor",
    "concat(",
    "xp_cmdshell",
    "information_schema",
)


def has_sql_payload_markers(text: str) -> bool:
    """True nếu chuỗi (URL/body đã giải mã) chứa dấu hiệu payload SQL Injection."""
    if not text:
        return False
    lowered = unquote(text).lower()
    return any(marker in lowered for marker in SQL_PAYLOAD_MARKERS)


def parse_timestamp(ts_val: Any) -> float:
    """Chuyển đổi timestamp ISO8601 hoặc số về float epoch seconds."""
    if ts_val is None:
        return datetime.now().timestamp()
    if isinstance(ts_val, (int, float)):
        return float(ts_val)
    if isinstance(ts_val, str):
        # Suricata EVE ISO format: 2026-10-12T07:15:23.123456+0000 or Z
        clean_ts = ts_val.strip()
        try:
            # Python datetime.fromisoformat hỗ trợ hầu hết các chuẩn ISO8601
            # Xử lý trường hợp đuôi +0000 không có dấu hai chấm
            if len(clean_ts) > 5 and clean_ts[-5] in ("+", "-") and ":" not in clean_ts[-5:]:
                clean_ts = clean_ts[:-2] + ":" + clean_ts[-2:]
            return datetime.fromisoformat(clean_ts).timestamp()
        except Exception:
            try:
                return float(clean_ts)
            except Exception:
                return datetime.now().timestamp()
    return datetime.now().timestamp()


def calculate_shannon_entropy(text: str) -> float:
    """Tính entropy Shannon cho chuỗi tham số (bits)."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


def extract_request_features(
    http_event: dict[str, Any],
    login_paths: list[str] | None = None,
    attack_user_agents: list[str] | None = None,
) -> dict[str, float]:
    """
    Trích xuất đặc trưng mức request từ sự kiện HTTP của Suricata sau khi giải mã URL.
    """
    login_paths = login_paths or ["/login", "/login.php", "/dvwa/login.php", "/admin"]
    attack_user_agents = attack_user_agents or ["sqlmap", "nikto", "hydra", "nmap", "gobuster"]

    http_data = http_event.get("http", {})
    raw_url = http_data.get("url", "") or ""
    # Giải mã URL
    decoded_url = unquote(raw_url)
    decoded_url_lower = decoded_url.lower()

    # 1. url_length
    url_length = float(len(decoded_url))

    # 2. special_char_count: đếm số ký tự trong tập ' " ; < > ( ) = -
    special_char_count = float(sum(1 for char in decoded_url if char in SPECIAL_CHARS))

    # 3. sql_keyword_count: đếm các từ khóa SQL injection không phân biệt hoa thường
    sql_kw_count = 0
    for kw in SQL_KEYWORDS:
        if kw == "--":
            sql_kw_count += decoded_url_lower.count("--")
        elif kw == "'or 1=1'":
            if "'or 1=1'" in decoded_url_lower or "or 1=1" in decoded_url_lower:
                sql_kw_count += 1
        else:
            # Dùng regex \b để tránh đếm nhầm substring không mong muốn
            matches = len(re.findall(rf"\b{re.escape(kw)}\b", decoded_url_lower))
            sql_kw_count += matches
    sql_keyword_count = float(sql_kw_count)

    # 4. param_entropy: entropy Shannon của chuỗi tham số (query string / payload)
    parsed = urlparse(decoded_url)
    param_string = parsed.query or ""
    # Nếu có post_body hoặc request_body trong http_data thì kết hợp thêm
    post_body = http_data.get("http_request_body", "") or ""
    if post_body:
        param_string = f"{param_string}&{post_body}" if param_string else post_body
    param_entropy = calculate_shannon_entropy(param_string)

    # 5. method_is_post: 1 nếu POST, 0 nếu khác
    method = (http_data.get("http_method", "") or "").upper()
    method_is_post = 1.0 if method == "POST" else 0.0

    # 6. status: HTTP status code
    status_raw = http_data.get("status", 200)
    try:
        status_val = float(status_raw) if status_raw is not None else 200.0
    except (ValueError, TypeError):
        status_val = 200.0

    # 7. is_login_path: so khớp với danh sách đường dẫn đăng nhập cấu hình được
    path = parsed.path.lower()
    is_login = any(lp.lower() in path for lp in login_paths)
    is_login_path = 1.0 if is_login else 0.0

    # 8. user_agent_flag: khớp danh sách User-Agent công cụ quét/tấn công
    ua = (http_data.get("http_user_agent", "") or "").lower()
    ua_flag = 1.0 if any(tool.lower() in ua for tool in attack_user_agents) else 0.0

    return {
        "url_length": url_length,
        "special_char_count": special_char_count,
        "sql_keyword_count": sql_keyword_count,
        "param_entropy": param_entropy,
        "method_is_post": method_is_post,
        "status": status_val,
        "is_login_path": is_login_path,
        "user_agent_flag": ua_flag,
    }


class SlidingWindowTracker:
    """
    Theo dõi và quản lý cửa sổ trượt (sliding window) theo IP nguồn.
    Duy trì N sự kiện gần nhất hoặc trong vòng T giây gần nhất.
    """

    def __init__(self, window_size_n: int = 20, window_time_t: float = 60.0):
        self.window_size_n = window_size_n
        self.window_time_t = window_time_t
        self.lock = threading.Lock()

        # Cấu trúc lưu trữ theo từng src_ip:
        # http_history: deque of dicts {'ts': float, 'url': str, 'status': int, 'is_login': bool}
        self.http_history: dict[str, deque[dict[str, Any]]] = {}
        # flow_history: deque of dicts {'ts': float, 'dest_port': int, 'duration': float, 'pkts': int, 'bytes': int}
        self.flow_history: dict[str, deque[dict[str, Any]]] = {}
        # alert_history: deque of dicts {'ts': float, 'signature': str, 'severity': int}
        self.alert_history: dict[str, deque[dict[str, Any]]] = {}

        # Cấu trúc lưu trữ lịch sử vector đặc trưng phục vụ LSTM: src_ip -> deque of list[float]
        self.vector_history: dict[str, deque[list[float]]] = {}

        # Thời điểm sự kiện gần nhất của mỗi IP (để dọn trạng thái khi hết tấn công)
        self.last_event_ts: dict[str, float] = {}
        self.last_seen_wall: dict[str, float] = {}

    def _cleanup_old_events(self, ip: str, current_ts: float) -> None:
        """Loại bỏ các sự kiện vượt quá T giây hoặc vượt quá N mục."""
        threshold_time = current_ts - self.window_time_t

        for hist_dict in (self.http_history, self.flow_history, self.alert_history):
            if ip in hist_dict:
                q = hist_dict[ip]
                # Lọc theo thời gian T
                while q and q[0]["ts"] < threshold_time:
                    q.popleft()
                # Giới hạn số lượng N
                while len(q) > self.window_size_n:
                    q.popleft()

        if ip in self.vector_history:
            while len(self.vector_history[ip]) > self.window_size_n:
                self.vector_history[ip].popleft()

    def add_event(self, raw_event: dict[str, Any], login_paths: list[str] | None = None) -> None:
        """Tiếp nhận một sự kiện Suricata EVE và cập nhật vào cửa sổ trượt tương ứng."""
        event_type = raw_event.get("event_type")
        src_ip = raw_event.get("src_ip")
        if not src_ip or not event_type:
            return

        ts = parse_timestamp(raw_event.get("timestamp"))
        wall_now = datetime.now().timestamp()
        # Tránh timestamp lệch đồng hồ (tương lai) khiến cửa sổ không bao giờ hết hạn
        if ts > wall_now + 5.0:
            ts = wall_now

        with self.lock:
            if event_type == "http":
                if src_ip not in self.http_history:
                    self.http_history[src_ip] = deque()
                http_obj = raw_event.get("http", {})
                raw_url = unquote(http_obj.get("url", "") or "")
                status_raw = http_obj.get("status", 200)
                try:
                    status_code = int(status_raw)
                except (ValueError, TypeError):
                    status_code = 200

                lp_list = login_paths or ["/login", "/login.php", "/dvwa/login.php"]
                is_login = any(lp in raw_url.lower() for lp in lp_list)

                self.http_history[src_ip].append(
                    {
                        "ts": ts,
                        "url": raw_url,
                        "status": status_code,
                        "is_login": is_login,
                    }
                )

            elif event_type == "flow":
                if src_ip not in self.flow_history:
                    self.flow_history[src_ip] = deque()
                flow_obj = raw_event.get("flow", {})
                dest_port = raw_event.get("dest_port", 80)
                try:
                    dest_port_val = int(dest_port)
                except (ValueError, TypeError):
                    dest_port_val = 80

                # pkts = pkts_toserver + pkts_toclient
                pkts = int(flow_obj.get("pkts_toserver", 0)) + int(flow_obj.get("pkts_toclient", 0))
                bytes_cnt = int(flow_obj.get("bytes_toserver", 0)) + int(flow_obj.get("bytes_toclient", 0))
                duration = float(flow_obj.get("age", 0.0))

                self.flow_history[src_ip].append(
                    {
                        "ts": ts,
                        "dest_port": dest_port_val,
                        "duration": duration,
                        "pkts": pkts,
                        "bytes": bytes_cnt,
                    }
                )

            elif event_type == "alert":
                if src_ip not in self.alert_history:
                    self.alert_history[src_ip] = deque()
                alert_obj = raw_event.get("alert", {})
                self.alert_history[src_ip].append(
                    {
                        "ts": ts,
                        "signature": alert_obj.get("signature", ""),
                        "severity": int(alert_obj.get("severity", 3)),
                    }
                )

            # Dọn dẹp sự kiện cũ
            self._cleanup_old_events(src_ip, ts)
            self.last_event_ts[src_ip] = ts
            self.last_seen_wall[src_ip] = wall_now

    def idle_ips(self, current_ts: float, idle_seconds: float) -> list[str]:
        """Danh sách các IP không còn sự kiện mới trong ``idle_seconds`` giây (theo đồng hồ hệ thống)."""
        with self.lock:
            return [
                ip
                for ip, last_wall in self.last_seen_wall.items()
                if current_ts - last_wall > idle_seconds
            ]

    def reset_ip(self, ip: str) -> None:
        """Xoá toàn bộ trạng thái cửa sổ trượt của một IP (sau khi hết tấn công)."""
        with self.lock:
            self.http_history.pop(ip, None)
            self.flow_history.pop(ip, None)
            self.alert_history.pop(ip, None)
            self.vector_history.pop(ip, None)
            self.last_event_ts.pop(ip, None)
            self.last_seen_wall.pop(ip, None)

    def extract_window_features(self, src_ip: str, current_ts: float | None = None) -> dict[str, float]:
        """
        Tính toán các đặc trưng mức cửa sổ cho IP nguồn dựa trên lịch sử HTTP, Flow, Alert.
        """
        if current_ts is None:
            # Ưu tiên thời điểm của sự kiện gần nhất của IP này thay vì đồng hồ
            # hiện tại. Nhờ vậy khi worker xử lý log trễ/backlog, cửa sổ trượt
            # vẫn được tính đúng theo thời gian của chính luồng sự kiện.
            with self.lock:
                current_ts = self.last_event_ts.get(src_ip) or datetime.now().timestamp()

        with self.lock:
            self._cleanup_old_events(src_ip, current_ts)

            http_q = list(self.http_history.get(src_ip, []))
            flow_q = list(self.flow_history.get(src_ip, []))
            alert_q = list(self.alert_history.get(src_ip, []))

        # --- Đặc trưng từ sự kiện HTTP ---
        n_http = len(http_q)
        if n_http > 1:
            times = [item["ts"] for item in http_q]
            duration_http = max(times) - min(times)
            req_rate = float(n_http) / max(duration_http, 1.0)
            time_diffs = [times[i] - times[i - 1] for i in range(1, len(times))]
            inter_request_time = float(sum(time_diffs) / len(time_diffs))
        elif n_http == 1:
            req_rate = 1.0
            inter_request_time = 0.0
        else:
            req_rate = 0.0
            inter_request_time = 0.0

        unique_urls = float(len({item["url"] for item in http_q})) if n_http > 0 else 0.0
        count_4xx = sum(1 for item in http_q if 400 <= item["status"] < 500)
        ratio_4xx = float(count_4xx / n_http) if n_http > 0 else 0.0

        # Login fail: status 401/403 hoặc thất bại trên đường dẫn login (VD: 404, 302, 200 lặp lại)
        login_fail_count = float(
            sum(
                1
                for item in http_q
                if item["is_login"] and (item["status"] in (401, 403, 400) or item["status"] >= 400)
            )
        )

        # --- Đặc trưng từ sự kiện Flow ---
        n_flow = len(flow_q)
        unique_dst_ports = float(len({item["dest_port"] for item in flow_q})) if n_flow > 0 else 0.0
        short_flow_count = float(sum(1 for item in flow_q if item["duration"] < 1.0 or item["bytes"] < 500))

        if n_flow > 0:
            flow_times = [item["ts"] for item in flow_q]
            flow_duration = max(max(flow_times) - min(flow_times), 1.0)
            total_pkts = sum(item["pkts"] for item in flow_q)
            total_bytes = sum(item["bytes"] for item in flow_q)
            pkts_per_sec = float(total_pkts) / flow_duration
            bytes_per_sec = float(total_bytes) / flow_duration
            # Concurrent flows ước lượng bằng số flow ghi nhận trong thời gian gần nhất
            concurrent_flows = float(n_flow)
            # Tốc độ gói lớn nhất của MỘT luồng (gói/giây) - dùng cho luật phát hiện DoS.
            # Khác với pkts_per_sec ở trên (tổng cửa sổ), chỉ số này không bị "thổi phồng"
            # khi một host bình thường mở nhiều kết nối ngắn trong cùng một giây.
            peak_flow_pps = max(
                item["pkts"] / max(item["duration"], 0.5) for item in flow_q
            )
            window_span_seconds = max(flow_times) - min(flow_times)
        else:
            pkts_per_sec = 0.0
            bytes_per_sec = 0.0
            concurrent_flows = 0.0
            peak_flow_pps = 0.0
            total_pkts = 0
            total_bytes = 0
            window_span_seconds = 0.0

        # --- Đặc trưng từ sự kiện Alert ---
        suricata_alert_count = float(len(alert_q))

        return {
            "req_rate": req_rate,
            "unique_urls": unique_urls,
            "ratio_4xx": ratio_4xx,
            "login_fail_count": login_fail_count,
            "inter_request_time": inter_request_time,
            "unique_dst_ports": unique_dst_ports,
            "short_flow_count": short_flow_count,
            "pkts_per_sec": pkts_per_sec,
            "bytes_per_sec": bytes_per_sec,
            "concurrent_flows": concurrent_flows,
            "suricata_alert_count": suricata_alert_count,
            # Các chỉ số bổ sung dùng cho luật phát hiện nhanh (không thuộc vector 19 đặc trưng)
            "peak_flow_pps": peak_flow_pps,
            "window_span_seconds": window_span_seconds,
            "window_total_pkts": float(total_pkts),
            "window_total_bytes": float(total_bytes),
            "window_http_count": float(n_http),
        }

    def get_full_feature_vector(
        self,
        http_event: dict[str, Any],
        login_paths: list[str] | None = None,
        attack_user_agents: list[str] | None = None,
    ) -> dict[str, float]:
        """
        Trích xuất kết hợp cả 19 đặc trưng: Request-level + Window-level.
        """
        src_ip = http_event.get("src_ip", "0.0.0.0")
        current_ts = parse_timestamp(http_event.get("timestamp"))

        # 1. Trích xuất đặc trưng mức request
        req_feat = extract_request_features(http_event, login_paths, attack_user_agents)

        # 2. Cập nhật sự kiện hiện tại vào cửa sổ trượt
        self.add_event(http_event, login_paths)

        # 3. Trích xuất đặc trưng mức cửa sổ
        win_feat = self.extract_window_features(src_ip, current_ts)

        # Hợp nhất
        full_feat: dict[str, float] = {}
        full_feat.update(req_feat)
        full_feat.update(win_feat)

        # Lưu lại vector float theo đúng thứ tự FEATURE_COLUMNS phục vụ chuỗi LSTM
        vec_list = [float(full_feat.get(col, 0.0)) for col in FEATURE_COLUMNS]
        with self.lock:
            if src_ip not in self.vector_history:
                self.vector_history[src_ip] = deque()
            self.vector_history[src_ip].append(vec_list)

        return full_feat

    def get_feature_sequence(self, src_ip: str, seq_len: int = 5) -> list[list[float]]:
        """
        Lấy chuỗi đặc trưng thời gian gần nhất (shape: [seq_len, 19]) cho mô hình LSTM.
        Nếu số lượng sự kiện chưa đủ seq_len, tự động đệm (padding) bằng cách nhân bản
        vector đầu tiên hoặc vector 0.
        """
        with self.lock:
            history = list(self.vector_history.get(src_ip, []))

        num_features = len(FEATURE_COLUMNS)
        if not history:
            return [[0.0] * num_features for _ in range(seq_len)]

        if len(history) >= seq_len:
            return history[-seq_len:]

        # Cần padding ở đầu chuỗi
        padding_count = seq_len - len(history)
        pad_vector = history[0]
        padded_seq = [pad_vector[:] for _ in range(padding_count)] + history
        return padded_seq

