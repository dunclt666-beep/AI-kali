"""
Điểm khởi chạy ứng dụng Desktop (Native Desktop Application Launcher).
Chạy toàn bộ backend AI-IDS (Collector, Worker, Flask) trên luồng ngầm
và hiển thị cửa sổ ứng dụng Desktop độc lập (PyWebView / App Window).

Cách chạy:
    python3 desktop_app.py
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path

# Đảm bảo đường dẫn gốc cho module
project_root = Path(__file__).resolve().parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.main import SystemManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("AI_IDS.DesktopApp")


def main():
    logger.info("Đang khởi động hệ thống AI IDS dưới dạng Desktop Application...")

    # 1. Khởi động backend AI IDS
    manager = SystemManager(config_path="config.yaml")
    manager.start()

    app_url = "http://127.0.0.1:5000"
    time.sleep(1.2)  # Chờ Flask server sẵn sàng

    # 2. Thử mở cửa sổ Native Desktop App bằng PyWebView
    # Nếu thiếu GTK/QT (Ubuntu Server) thì tự rớt về browser, không crash
    def _run_browser_mode():
        import subprocess
        opened = False
        for browser_cmd in [
            ["google-chrome", f"--app={app_url}"],
            ["chromium-browser", f"--app={app_url}"],
            ["microsoft-edge", f"--app={app_url}"],
        ]:
            try:
                subprocess.Popen(browser_cmd)
                opened = True
                break
            except FileNotFoundError:
                continue
        if not opened:
            try:
                webbrowser.open(app_url)
            except Exception:
                pass
        logger.info("Ứng dụng đang chạy tại: %s. Nhấn Ctrl+C để dừng.", app_url)
        try:
            while manager.running.is_set():
                time.sleep(1.0)
        except KeyboardInterrupt:
            manager.stop()

    try:
        import webview
        logger.info("Mở cửa sổ Desktop GUI (PyWebView)...")
        webview.create_window(
            title="AI Early Web Attack Detection System - SOC Desktop",
            url=app_url,
            width=1280,
            height=820,
            resizable=True,
            min_size=(960, 640),
        )
        try:
            webview.start()
        except Exception as e:
            logger.warning("pywebview lỗi GUI (%s), chuyển sang browser mode...", e)
            _run_browser_mode()
            return
        manager.stop()
        sys.exit(0)

    except ImportError:
        logger.warning("Thư viện pywebview chưa được cài đặt (pip install pywebview).")
        _run_browser_mode()


if __name__ == "__main__":
    main()
