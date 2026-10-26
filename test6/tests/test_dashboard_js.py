"""Kiểm tra cú pháp JavaScript nhúng trong Dashboard.

Dashboard dùng một template HTML lớn chứa inline script. Một chuỗi ``\\n``
không được escape đúng trong Python sẽ biến thành newline thật trong JS,
khiến toàn bộ script không chạy: giao diện hiện khung tĩnh, mọi nút bấm và
số liệu đều không hoạt động. Test này render trang thật và gọi ``node --check``
để chặn lỗi đó tái diễn.
"""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from src import dashboard


def test_dashboard_inline_javascript_is_syntactically_valid(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Không có node để kiểm tra cú pháp JavaScript")

    response = dashboard.app.test_client().get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)

    scripts = re.findall(
        r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S
    )
    assert scripts, "Dashboard phải có inline script"

    script_path = tmp_path / "dashboard_inline.js"
    script_path.write_text(scripts[-1], encoding="utf-8")

    result = subprocess.run(
        [node, "--check", str(script_path)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
