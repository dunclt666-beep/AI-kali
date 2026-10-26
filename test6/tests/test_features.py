"""
Unit tests kiểm thử module trích xuất đặc trưng (src/features.py).
"""

from __future__ import annotations

import pytest

from src.features import (
    FEATURE_COLUMNS,
    SlidingWindowTracker,
    calculate_shannon_entropy,
    extract_request_features,
    parse_timestamp,
)


def test_calculate_shannon_entropy():
    # Chuỗi rỗng -> entropy = 0
    assert calculate_shannon_entropy("") == 0.0
    # Chuỗi đồng nhất -> entropy = 0
    assert calculate_shannon_entropy("aaaaaa") == 0.0
    # Chuỗi có độ phức tạp cao hơn -> entropy > 0
    entropy_val = calculate_shannon_entropy("admin123!@#$")
    assert entropy_val > 2.0


def test_extract_request_features_sqli():
    # Sự kiện HTTP chứa chuỗi SQL Injection đã URL-encode
    http_event = {
        "timestamp": "2026-10-12T12:00:00Z",
        "src_ip": "192.168.1.150",
        "http": {
            "http_method": "GET",
            "url": "/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20null,version()--&Submit=Submit",
            "status": 200,
            "http_user_agent": "sqlmap/1.5",
        },
    }

    login_paths = ["/login", "/dvwa/login.php"]
    attack_uas = ["sqlmap", "nikto"]

    features = extract_request_features(http_event, login_paths, attack_uas)

    # Kiểm tra giải mã URL
    assert features["url_length"] > 30
    # Đếm ký tự đặc biệt ' - ( ) =
    assert features["special_char_count"] >= 4
    # Đếm từ khóa union, select, --
    assert features["sql_keyword_count"] >= 2
    # User agent sqlmap
    assert features["user_agent_flag"] == 1.0
    # Không phải POST
    assert features["method_is_post"] == 0.0
    # Không phải login path
    assert features["is_login_path"] == 0.0


def test_extract_request_features_login_post():
    http_event = {
        "timestamp": "2026-10-12T12:00:05Z",
        "src_ip": "192.168.1.190",
        "http": {
            "http_method": "POST",
            "url": "/dvwa/login.php",
            "status": 401,
            "http_user_agent": "hydra/9.2",
            "http_request_body": "username=admin&password=123",
        },
    }

    features = extract_request_features(
        http_event,
        login_paths=["/dvwa/login.php"],
        attack_user_agents=["hydra"],
    )

    assert features["method_is_post"] == 1.0
    assert features["is_login_path"] == 1.0
    assert features["status"] == 401.0
    assert features["user_agent_flag"] == 1.0
    assert features["param_entropy"] > 0.0


def test_sliding_window_tracker():
    tracker = SlidingWindowTracker(window_size_n=5, window_time_t=60.0)
    src_ip = "192.168.1.200"

    # Thêm 3 sự kiện HTTP
    for i in range(3):
        tracker.add_event({
            "timestamp": f"2026-10-12T12:00:0{i}Z",
            "event_type": "http",
            "src_ip": src_ip,
            "http": {
                "http_method": "GET",
                "url": f"/page_{i}",
                "status": 404 if i > 0 else 200,
            },
        })

    # Thêm 1 sự kiện flow
    tracker.add_event({
        "timestamp": "2026-10-12T12:00:02Z",
        "event_type": "flow",
        "src_ip": src_ip,
        "dest_port": 80,
        "flow": {
            "pkts_toserver": 10,
            "pkts_toclient": 10,
            "bytes_toserver": 1000,
            "bytes_toclient": 2000,
            "age": 0.5,
        },
    })

    # Thêm 1 sự kiện alert
    tracker.add_event({
        "timestamp": "2026-10-12T12:00:03Z",
        "event_type": "alert",
        "src_ip": src_ip,
        "alert": {"signature": "Test Alert", "severity": 1},
    })

    # Truyền current_ts khớp với timestamp của event mới nhất (12:00:03Z),
    # nếu không hàm sẽ mặc định dùng datetime.now() và xoá hết event 2026-10-12
    # khỏi cửa sổ trượt (vì older hơn window_time_t=60s).
    current_ts = parse_timestamp("2026-10-12T12:00:03Z")
    win_feats = tracker.extract_window_features(src_ip, current_ts=current_ts)

    assert win_feats["unique_urls"] == 3.0
    assert win_feats["ratio_4xx"] == pytest.approx(2.0 / 3.0, 0.01)
    assert win_feats["suricata_alert_count"] == 1.0
    assert win_feats["concurrent_flows"] == 1.0
    assert win_feats["unique_dst_ports"] == 1.0


def test_full_feature_columns_completeness():
    tracker = SlidingWindowTracker()
    dummy_event = {
        "timestamp": "2026-10-12T12:00:00Z",
        "event_type": "http",
        "src_ip": "10.0.0.1",
        "http": {"http_method": "GET", "url": "/", "status": 200},
    }
    full_vector = tracker.get_full_feature_vector(dummy_event)

    # Đảm bảo đủ tất cả 19 đặc trưng
    for col in FEATURE_COLUMNS:
        assert col in full_vector, f"Thiếu đặc trưng: {col}"
