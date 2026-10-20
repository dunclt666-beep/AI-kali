"""
Unit tests kiểm thử module tính điểm phát hiện sớm (src/scorer.py).
"""

from __future__ import annotations

import pytest

from src.scorer import EarlyDetectionScorer


def test_scorer_ema_formula_calculation():
    # Khởi tạo scorer với alpha = 0.7, theta = 0.7, high = 0.9
    scorer = EarlyDetectionScorer(alpha=0.7, theta=0.7, high_threshold=0.9)
    src_ip = "192.168.1.100"

    # Bước 1: p_1 = 0.8
    # S_1 = 0.7 * 0 + 0.3 * 0.8 = 0.24
    s1, sev1, alert1 = scorer.update_score(src_ip, p_t=0.8)
    assert s1 == pytest.approx(0.24, 0.001)
    assert not alert1
    assert sev1 is None

    # Bước 2: p_2 = 0.9
    # S_2 = 0.7 * 0.24 + 0.3 * 0.9 = 0.168 + 0.270 = 0.438
    s2, sev2, alert2 = scorer.update_score(src_ip, p_t=0.9)
    assert s2 == pytest.approx(0.438, 0.001)
    assert not alert2
    assert sev2 is None

    # Bước 3: p_3 = 0.95
    # S_3 = 0.7 * 0.438 + 0.3 * 0.95 = 0.3066 + 0.285 = 0.5916
    s3, sev3, alert3 = scorer.update_score(src_ip, p_t=0.95)
    assert s3 == pytest.approx(0.5916, 0.001)
    assert not alert3

    # Bước 4: p_4 = 0.98
    # S_4 = 0.7 * 0.5916 + 0.3 * 0.98 = 0.41412 + 0.294 = 0.70812 >= 0.7
    # Vượt theta (0.7) -> Kích hoạt cảnh báo mức 'Trung bình'
    s4, sev4, alert4 = scorer.update_score(src_ip, p_t=0.98)
    assert s4 >= 0.7
    assert alert4
    assert sev4 == "Trung bình"


def test_scorer_high_severity():
    scorer = EarlyDetectionScorer(alpha=0.5, theta=0.7, high_threshold=0.9)
    src_ip = "192.168.1.105"

    # Cho chuỗi p_t cao liên tiếp để đẩy S_t vượt 0.9
    for _ in range(5):
        s, sev, alert = scorer.update_score(src_ip, p_t=0.98)

    assert s >= 0.9
    assert alert
    assert sev == "Cao"


def test_scorer_reset_and_isolation():
    scorer = EarlyDetectionScorer()
    ip1 = "10.0.0.1"
    ip2 = "10.0.0.2"

    scorer.update_score(ip1, p_t=0.8)
    scorer.update_score(ip2, p_t=0.2)

    assert scorer.get_score(ip1) > 0.0
    assert scorer.get_score(ip2) > 0.0

    # Reset IP1 không ảnh hưởng IP2
    scorer.reset_score(ip1)
    assert scorer.get_score(ip1) == 0.0
    assert scorer.get_score(ip2) > 0.0
