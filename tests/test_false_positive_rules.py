"""
Unit tests chống báo nhầm (false positive) và kiểm tra nhận diện IP tấn công.

Bối cảnh: app chạy trên máy web server, lưu lượng hợp lệ của chính máy đó
(SSH/DNS/apt/dashboard) từng bị báo nhầm thành SCAN/DOS và IP bị tố chính là
IP của máy bị tấn công. Các test dưới đây khóa lại hành vi đúng.
"""

from __future__ import annotations

from src.features import SlidingWindowTracker
from src.main import (
    DEFAULT_DETECTION,
    SystemManager,
    evaluate_flow_rules,
    evaluate_http_fasttrack,
)


def _make_manager(
    server_ips: set[str] | None = None,
    local_ips: set[str] | None = None,
) -> SystemManager:
    """Tạo SystemManager 'rỗng' (không kết nối PostgreSQL) để test logic thuần."""
    manager = SystemManager.__new__(SystemManager)
    manager.attacker_selection = "auto"
    manager.server_ports = {
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389,
        5432, 5900, 6379, 8000, 8008, 8080, 8443, 8888,
    }
    manager.server_ips = server_ips or set()
    manager.protected_networks = []
    manager.protect_local_ips = bool(local_ips)
    manager.local_ips = local_ips or set()
    return manager


# ---------------------------------------------------------------------------
# 1. Luật Flow: không báo nhầm lưu lượng bình thường
# ---------------------------------------------------------------------------

def _flow(ip: str, dest_port: int, pkts_to: int, pkts_back: int, age: float, ts: str = "2026-10-20T00:00:00Z"):
    return {
        "timestamp": ts,
        "event_type": "flow",
        "src_ip": ip,
        "dest_port": dest_port,
        "flow": {
            "pkts_toserver": pkts_to,
            "pkts_toclient": pkts_back,
            "bytes_toserver": 1200,
            "bytes_toclient": 4000,
            "age": age,
        },
    }


def test_benign_server_own_traffic_does_not_alert():
    """SSH tới pfSense + DNS + apt + HTTPS + Postgres của máy web server -> không cảnh báo."""
    tracker = SlidingWindowTracker(window_size_n=20, window_time_t=60)
    victim = "192.168.78.132"

    tracker.add_event(_flow(victim, 22, 30, 25, 120.0, "2026-10-20T00:00:01Z"))
    tracker.add_event(_flow(victim, 53, 2, 2, 0.4, "2026-10-20T00:00:02Z"))
    tracker.add_event(_flow(victim, 80, 20, 40, 3.0, "2026-10-20T00:00:03Z"))
    tracker.add_event(_flow(victim, 443, 35, 40, 6.0, "2026-10-20T00:00:04Z"))
    tracker.add_event(_flow(victim, 5432, 12, 12, 2.0, "2026-10-20T00:00:05Z"))

    win_feat = tracker.extract_window_features(victim)
    assert win_feat["unique_dst_ports"] == 5.0
    assert evaluate_flow_rules(win_feat, DEFAULT_DETECTION) is None


def test_single_normal_flow_with_many_packets_does_not_alert():
    """Một luồng tải file bình thường 300 gói vẫn không được coi là DoS."""
    tracker = SlidingWindowTracker(window_size_n=20, window_time_t=60)
    client = "192.168.78.101"

    tracker.add_event(_flow(client, 80, 150, 150, 8.0))

    win_feat = tracker.extract_window_features(client)
    assert evaluate_flow_rules(win_feat, DEFAULT_DETECTION) is None


def test_port_scan_is_still_detected():
    """nmap quét nhiều cổng khác nhau -> vẫn phải phát hiện SCAN."""
    tracker = SlidingWindowTracker(window_size_n=20, window_time_t=60)
    attacker = "192.168.78.150"

    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]):
        tracker.add_event(_flow(attacker, port, 1, 0, 0.01, f"2026-10-20T00:00:{i:02d}Z"))

    win_feat = tracker.extract_window_features(attacker)
    assert evaluate_flow_rules(win_feat, DEFAULT_DETECTION) == "scan"


def test_syn_flood_is_still_detected():
    """hping3 --flood: một luồng tốc độ gói cực cao -> vẫn phải phát hiện DOS."""
    tracker = SlidingWindowTracker(window_size_n=20, window_time_t=60)
    attacker = "192.168.78.150"

    tracker.add_event(_flow(attacker, 80, 5000, 0, 1.0))

    win_feat = tracker.extract_window_features(attacker)
    assert evaluate_flow_rules(win_feat, DEFAULT_DETECTION) == "dos"


# ---------------------------------------------------------------------------
# 2. Luật HTTP fast-track: không báo nhầm URL/UA hợp lệ
# ---------------------------------------------------------------------------

def _http_features(**over):
    base = {
        "url_length": 30.0,
        "special_char_count": 1.0,
        "sql_keyword_count": 0.0,
        "param_entropy": 1.8,
        "method_is_post": 0.0,
        "status": 200.0,
        "is_login_path": 0.0,
        "user_agent_flag": 0.0,
        "req_rate": 0.5,
        "unique_urls": 3.0,
        "ratio_4xx": 0.1,
        "login_fail_count": 0.0,
        "inter_request_time": 2.0,
        "unique_dst_ports": 1.0,
        "short_flow_count": 0.0,
        "pkts_per_sec": 20.0,
        "bytes_per_sec": 3000.0,
        "concurrent_flows": 1.0,
        "suricata_alert_count": 0.0,
        "peak_flow_pps": 20.0,
        "window_http_count": 3.0,
    }
    base.update(over)
    return base


def test_benign_keyword_url_is_not_sql_injection():
    """URL hợp lệ chứa từ khóa SQL (/delete.php, /update_profile.php) không được báo SQLi."""
    feats = _http_features(sql_keyword_count=1.0, special_char_count=2.0)
    assert evaluate_http_fasttrack(
        feats, "Mozilla/5.0 (Windows NT 10.0) Firefox/121", "/delete.php?id=3", DEFAULT_DETECTION
    ) is None
    assert evaluate_http_fasttrack(
        feats, "Mozilla/5.0 (Windows NT 10.0) Firefox/121", "/update_profile.php", DEFAULT_DETECTION
    ) is None


def test_real_sql_injection_is_detected():
    feats = _http_features(sql_keyword_count=3.0, special_char_count=7.0)
    result = evaluate_http_fasttrack(
        feats,
        "sqlmap/1.6#stable (https://sqlmap.org)",
        "/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20null,version()--&Submit=Submit",
        DEFAULT_DETECTION,
    )
    assert result is not None
    assert result[0] == "sqli"
    assert result[1] >= 0.95


def test_sql_keyword_with_payload_marker_is_detected():
    feats = _http_features(sql_keyword_count=1.0, special_char_count=3.0)
    result = evaluate_http_fasttrack(
        feats,
        "Mozilla/5.0",
        "/product?id=1%27%20OR%201=1--",
        DEFAULT_DETECTION,
    )
    assert result is not None
    assert result[0] == "sqli"


def test_single_curl_healthcheck_is_not_alert():
    feats = _http_features()
    assert evaluate_http_fasttrack(feats, "curl/8.5.0", "/health", DEFAULT_DETECTION) is None


def test_directory_scan_and_bruteforce_are_detected():
    scan_feats = _http_features(ratio_4xx=0.9, unique_urls=25.0)
    scan_result = evaluate_http_fasttrack(scan_feats, "Mozilla/5.0", "/admin.php", DEFAULT_DETECTION)
    assert scan_result is not None and scan_result[0] == "scan"

    brute_feats = _http_features(login_fail_count=8.0, is_login_path=1.0, status=401.0)
    brute_result = evaluate_http_fasttrack(brute_feats, "Mozilla/5.0", "/login.php", DEFAULT_DETECTION)
    assert brute_result is not None and brute_result[0] == "bruteforce"


# ---------------------------------------------------------------------------
# 3. Nhận diện IP tấn công: không bao giờ tố cáo phía server / máy cục bộ
# ---------------------------------------------------------------------------

def test_attacker_ip_from_attack_flow_is_the_client():
    manager = _make_manager(server_ips={"192.168.78.132"}, local_ips={"192.168.78.132"})
    event = {
        "event_type": "http",
        "src_ip": "192.168.78.150",
        "src_port": 45000,
        "dest_ip": "192.168.78.132",
        "dest_port": 80,
    }
    assert manager._resolve_attacker_ip(event) == "192.168.78.150"
    assert manager._is_protected_ip("192.168.78.150") is False


def test_response_direction_of_attack_is_attributed_to_attacker():
    manager = _make_manager(server_ips={"192.168.78.132"}, local_ips={"192.168.78.132"})
    event = {
        "event_type": "flow",
        "src_ip": "192.168.78.132",
        "src_port": 80,
        "dest_ip": "192.168.78.150",
        "dest_port": 45001,
    }
    assert manager._resolve_attacker_ip(event) == "192.168.78.150"


def test_web_server_own_traffic_is_never_reported_as_attacker():
    manager = _make_manager(server_ips={"192.168.78.132"}, local_ips={"192.168.78.132"})

    # SSH của chính máy web server tới pfSense: cổng nguồn tạm -> client chính là server
    ssh_event = {
        "event_type": "flow",
        "src_ip": "192.168.78.132",
        "src_port": 41000,
        "dest_ip": "192.168.78.136",
        "dest_port": 22,
    }
    attacker = manager._resolve_attacker_ip(ssh_event)
    assert attacker == "192.168.78.132"
    # ... nhưng IP này nằm trong danh sách bảo vệ nên sự kiện bị bỏ qua (không cảnh báo)
    assert manager._is_protected_ip(attacker) is True

    # Lưu lượng không rõ cổng do server tự khởi tạo -> không gán cho IP nào khác
    unknown_event = {
        "event_type": "flow",
        "src_ip": "192.168.78.132",
        "src_port": 42000,
        "dest_ip": "192.168.78.99",
        "dest_port": 9000,
    }
    assert manager._resolve_attacker_ip(unknown_event) is None


def test_local_ip_is_protected_by_default():
    manager = _make_manager(local_ips={"192.168.78.132"})
    assert manager._is_protected_ip("192.168.78.132") is True
    assert manager._is_protected_ip("192.168.78.150") is False
