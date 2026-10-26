"""
Unit tests kiểm thử chế độ phát hiện siêu tốc (Fast Detection) và chế độ chỉ cảnh báo.
"""

from __future__ import annotations

import pytest

from src.features import SlidingWindowTracker
from src.scorer import EarlyDetectionScorer


def test_fast_detection_nmap_port_scan_flow():
    """Kiểm tra phát hiện Nmap SYN Scan chỉ qua sự kiện Flow."""
    tracker = SlidingWindowTracker(window_size_n=50, window_time_t=60)
    scorer = EarlyDetectionScorer(alpha=0.4, theta=0.6, fast_detection=True)
    kali_ip = "192.168.1.200"

    # Giả lập Nmap -sS quét 10 cổng khác nhau
    for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080]:
        tracker.add_event({
            "timestamp": "2026-10-19T22:00:00Z",
            "event_type": "flow",
            "src_ip": kali_ip,
            "dest_port": port,
            "flow": {"pkts_toserver": 1, "bytes_toserver": 60, "age": 0.01},
        })

    win_feat = tracker.extract_window_features(kali_ip)
    assert win_feat["unique_dst_ports"] >= 5.0

    # Kích hoạt đánh giá phát hiện nhanh
    score, severity, is_alert = scorer.update_score(kali_ip, p_t=0.95)
    assert is_alert is True
    assert score >= 0.85
    assert severity in ("Cao", "Trung bình")


def test_fast_detection_dos_syn_flood_flow():
    """Kiểm tra phát hiện DoS SYN Flood (hping3) qua Flow."""
    tracker = SlidingWindowTracker(window_size_n=50, window_time_t=60)
    scorer = EarlyDetectionScorer(alpha=0.4, theta=0.6, fast_detection=True)
    kali_ip = "192.168.1.201"

    for i in range(25):
        tracker.add_event({
            "timestamp": "2026-10-19T22:00:00Z",
            "event_type": "flow",
            "src_ip": kali_ip,
            "dest_port": 80,
            "flow": {"pkts_toserver": 50, "bytes_toserver": 2500, "age": 0.05},
        })

    win_feat = tracker.extract_window_features(kali_ip)
    assert win_feat["short_flow_count"] >= 18.0

    score, severity, is_alert = scorer.update_score(kali_ip, p_t=0.96)
    assert is_alert is True
    assert score >= 0.85
