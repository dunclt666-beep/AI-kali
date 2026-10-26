"""Kiểm thử bộ lọc sự kiện cũ (chống phát lại log từ file/pfSense).

Khi cuộc tấn công đã dừng, các dòng log cũ có thể bị đọc lại do logrotate,
đồng bộ lại từ pfSense hoặc file log được mở lại. Bộ lọc phải bảo đảm những
sự kiện đó không đi vào pipeline chấm điểm và không sinh cảnh báo mới.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from src.main import is_stale_event


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def test_recent_event_is_not_stale():
    now = time.time()
    event = {"timestamp": _iso(now - 5), "event_type": "http"}
    assert is_stale_event(event, max_age_seconds=60, now_ts=now) is False


def test_old_event_is_stale():
    now = time.time()
    event = {"timestamp": _iso(now - 3600), "event_type": "alert"}
    assert is_stale_event(event, max_age_seconds=60, now_ts=now) is True


def test_disabled_filter_accepts_old_event():
    now = time.time()
    event = {"timestamp": _iso(now - 3600), "event_type": "alert"}
    assert is_stale_event(event, max_age_seconds=0, now_ts=now) is False


def test_event_without_timestamp_is_not_dropped():
    assert is_stale_event({"event_type": "flow"}, max_age_seconds=60) is False


def test_future_event_is_not_stale():
    now = time.time()
    event = {"timestamp": _iso(now + 10), "event_type": "http"}
    assert is_stale_event(event, max_age_seconds=60, now_ts=now) is False
