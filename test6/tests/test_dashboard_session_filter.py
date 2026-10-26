"""Kiểm thử dashboard chỉ hiển thị cảnh báo của phiên chạy hiện tại.

Cảnh báo cũ vẫn nằm trong PostgreSQL, nhưng API mặc định phải truyền mốc
``since=session_started_at`` để không hiển thị lại chúng sau khi khởi động.
Nút "Hiện cảnh báo cũ" gửi ``include_history=1`` để xem toàn bộ lịch sử.
"""

from __future__ import annotations

from src import dashboard


def _client_with_fake_alerts(monkeypatch, captured: dict):
    def fake_get_alerts(limit=50, status=None, since=None):
        captured["since"] = since
        return []

    monkeypatch.setattr(dashboard, "get_alerts", fake_get_alerts)
    monkeypatch.setitem(
        dashboard.APP_CONTEXT, "config", {"alert": {"show_only_current_session": True}}
    )
    monkeypatch.setitem(
        dashboard.APP_CONTEXT, "session_started_at", "2026-10-20T08:00:00"
    )
    return dashboard.app.test_client()


def test_alerts_default_to_current_session(monkeypatch):
    captured: dict = {}
    client = _client_with_fake_alerts(monkeypatch, captured)

    response = client.get("/api/alerts")

    assert response.status_code == 200
    assert captured["since"] == "2026-10-20T08:00:00"
    assert response.get_json()["showing_history"] is False


def test_alerts_can_include_history(monkeypatch):
    captured: dict = {}
    client = _client_with_fake_alerts(monkeypatch, captured)

    response = client.get("/api/alerts?include_history=1")

    assert response.status_code == 200
    assert captured["since"] is None
    assert response.get_json()["showing_history"] is True


def test_stats_use_the_same_session_filter(monkeypatch):
    captured: dict = {}

    def fake_get_stats(since=None):
        captured["since"] = since
        return {"by_type": {}, "by_status": {}, "time_series": []}

    monkeypatch.setattr(dashboard, "get_stats", fake_get_stats)
    monkeypatch.setitem(
        dashboard.APP_CONTEXT, "config", {"alert": {"show_only_current_session": True}}
    )
    monkeypatch.setitem(
        dashboard.APP_CONTEXT, "session_started_at", "2026-10-20T08:00:00"
    )
    client = dashboard.app.test_client()

    assert client.get("/api/stats").status_code == 200
    assert captured["since"] == "2026-10-20T08:00:00"

    assert client.get("/api/stats?include_history=1").status_code == 200
    assert captured["since"] is None
