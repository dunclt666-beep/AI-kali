"""
Module thu thập log Suricata EVE (Log Collector).
Đọc tệp eve.json theo phương thức 'tail -f', tự động xử lý log xoay vòng (logrotate/inode tracking),
đẩy sự kiện đã phân tích trực tiếp vào PostgreSQL thông qua PostgresStore.
"""

from __future__ import annotations

import json
import logging
import os

import threading
import time
from typing import Any

logger = logging.getLogger("AI_IDS.Collector")


class LogCollector(threading.Thread):
    """
    Luồng thu thập log Suricata EVE JSON không chặn (non-blocking).
    """

    def __init__(
        self,
        log_path: str,
        pg_store: Any,
        poll_interval: float = 0.2,
        start_at_end: bool = True,
    ):
        super().__init__(name="LogCollectorThread", daemon=True)
        self.log_path = os.path.abspath(log_path)
        self.pg_store = pg_store
        self.poll_interval = poll_interval
        self.start_at_end = bool(start_at_end)
        self._stop_event = threading.Event()
        self.processed_events = 0
        self.malformed_lines = 0
        self.last_event_at: float | None = None
        self.last_inode: int | None = None
        self.last_pos: int = 0

    def stop(self) -> None:
        """Dừng luồng thu thập log."""
        self._stop_event.set()

    def is_stopped(self) -> bool:
        """Kiểm tra trạng thái dừng."""
        return self._stop_event.is_set()

    def _get_file_identifier(self) -> tuple[int | None, int]:
        """Lấy bộ nhận diện tệp (inode trên Linux/Unix hoặc mtime/size trên Windows) và kích thước tệp."""
        try:
            stat_info = os.stat(self.log_path)
            # st_ino có sẵn trên Unix, trên Windows có thể là 0 hoặc id duy nhất
            inode = getattr(stat_info, "st_ino", None)
            return inode, stat_info.st_size
        except OSError:
            return None, 0

    def run(self) -> None:
        """Vòng lặp chính đọc log liên tục."""
        logger.info("Khởi động LogCollector theo dõi tệp: %s", self.log_path)
        file_obj = None

        while not self.is_stopped():
            # 1. Nếu tệp chưa tồn tại, chờ đợi
            if not os.path.exists(self.log_path):
                time.sleep(self.poll_interval)
                continue

            current_inode, current_size = self._get_file_identifier()

            # 2. Xử lý mở tệp lần đầu hoặc khi tệp bị xoay vòng (logrotate)
            file_rotated = False
            if file_obj is None:
                try:
                    file_obj = open(self.log_path, "r", encoding="utf-8", errors="replace")
                    # Mặc định bỏ qua nội dung cũ (chỉ đọc sự kiện mới xuất hiện sau khi
                    # khởi động). Đặt start_at_end=false trong config nếu muốn phát lại
                    # file log mẫu (ví dụ data/sample_eve.json) để demo.
                    if self.start_at_end:
                        file_obj.seek(0, os.SEEK_END)
                    self.last_pos = file_obj.tell()
                    self.last_inode = current_inode
                    logger.info("Đã mở tệp log %s (vị trí: %d, inode: %s)", self.log_path, self.last_pos, self.last_inode)
                except Exception as ex:
                    logger.warning("Không thể mở tệp log: %s", ex)
                    time.sleep(self.poll_interval)
                    continue
            else:
                # Kiểm tra inode thay đổi hoặc kích thước tệp bị thu nhỏ đột ngột (truncate)
                if (self.last_inode is not None and current_inode != self.last_inode) or (current_size < self.last_pos):
                    file_rotated = True
                    logger.info("Phát hiện tệp log đã bị xoay vòng hoặc truncate. Đang mở lại tệp mới...")

            if file_rotated:
                try:
                    # Đọc nốt dữ liệu còn lại trong tệp cũ nếu còn
                    self._read_available_lines(file_obj)
                    file_obj.close()
                except Exception:
                    pass
                file_obj = None
                self.last_pos = 0
                self.last_inode = current_inode
                continue

            # 3. Đọc dữ liệu mới từ tệp
            self._read_available_lines(file_obj)
            time.sleep(self.poll_interval)

        # Đóng tệp khi luồng kết thúc
        if file_obj:
            try:
                file_obj.close()
            except Exception:
                pass
        logger.info("LogCollector đã dừng.")

    def _read_available_lines(self, file_obj) -> None:
        """Đọc tất cả các dòng hoàn chỉnh có sẵn tại thời điểm hiện tại."""
        while not self.is_stopped():
            current_pos = file_obj.tell()
            line = file_obj.readline()

            if not line:
                # Chưa có dữ liệu mới
                break

            # Kiểm tra xem dòng đã kết thúc bằng ký tự xuống dòng chưa (tránh đọc dòng dở dang)
            if not line.endswith("\n"):
                # Dòng chưa ghi xong, quay lại vị trí trước đó và chờ lượt sau
                file_obj.seek(current_pos)
                break

            self.last_pos = file_obj.tell()
            stripped_line = line.strip()
            if not stripped_line:
                continue

            try:
                event_data = json.loads(stripped_line)
                # Đẩy sự kiện vào PostgreSQL (raw_events). Worker AI sẽ đọc
                # các bản ghi processing_status='pending' từ đây.
                saved = self.pg_store.save_event(event_data)
                if saved:
                    self.processed_events += 1
                    self.last_event_at = time.time()
                else:
                    logger.error(
                        "Không lưu được sự kiện vào PostgreSQL: type=%s",
                        event_data.get("event_type"),
                    )
            except json.JSONDecodeError:
                self.malformed_lines += 1
                logger.debug("Bỏ qua dòng log JSON không hợp lệ: %s", stripped_line[:100])
