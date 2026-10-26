"""
Module quản lý cảnh báo và đồng hồ đếm ngược (Alert Manager).
Nối kết giữa Scorer, Database và Blocker:
- Sinh cảnh báo và lưu vào PostgreSQL
- Đếm ngược thời gian chờ phản hồi từ quản trị viên (mặc định 5s)
- Tự động chặn IP nếu hết giờ mà không có phản hồi
- Bỏ qua nếu IP nằm trong whitelist
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime
from typing import Any

from src.blocker import IPBlocker
from src.db import (
    add_alert,
    get_alert_by_id,
    is_in_whitelist,
    is_ip_blocked,
    update_alert_status,
)
from src.scorer import EarlyDetectionScorer

logger = logging.getLogger("AI_IDS.AlertManager")


class AlertManager:
    """
    Quản lý vòng đời của các cảnh báo phát hiện sớm và cơ chế tự động chặn đếm ngược.
    """

    def __init__(
        self,
        scorer: EarlyDetectionScorer,
        blocker: IPBlocker,
        countdown_seconds: int = 5,
        auto_block_enabled: bool = True,
        cooldown_seconds: int = 30,
    ):
        self.scorer = scorer
        self.blocker = blocker
        self.countdown_seconds = countdown_seconds
        self.auto_block_enabled = auto_block_enabled
        # Khoảng lặng tối thiểu giữa 2 cảnh báo cùng IP + cùng loại tấn công.
        # Nhờ vậy khi cuộc tấn công dừng, hệ thống không báo lặp vô hạn.
        self.cooldown_seconds = max(0, int(cooldown_seconds))

        # Lưu trữ các đồng hồ đếm ngược đang chạy: alert_id -> {timer, expire_ts, src_ip, ...}
        self.active_timers: dict[int, dict[str, Any]] = {}
        # Lần cuối tạo cảnh báo theo (src_ip, attack_type)
        self._last_alerts: dict[tuple[str, str], float] = {}
        self.lock = threading.Lock()

    def process_score(
        self,
        src_ip: str,
        attack_type: str,
        score: float,
        severity: str,
        dest_ip: str | None = None,
        source_of_detection: str | None = None,
        confidence: float | None = None,
        evidence: Any = None,
        alert_timestamp: datetime | None = None,
    ) -> int | None:
        """
        Tiếp nhận kết quả tính điểm. Nếu vượt ngưỡng, tạo cảnh báo và khởi động đếm ngược.
        """
        # Kiểm tra whitelist
        if is_in_whitelist(src_ip):
            logger.info("IP %s nằm trong whitelist, bỏ qua tạo cảnh báo.", src_ip)
            return None

        # Kiểm tra nếu đã bị chặn rồi
        if is_ip_blocked(src_ip):
            logger.debug("IP %s đã bị chặn trước đó.", src_ip)
            return None

        with self.lock:
            # Kiểm tra xem IP này đã có cảnh báo đang đếm ngược chưa
            for aid, item in self.active_timers.items():
                if item["src_ip"] == src_ip:
                    return aid

            now = time.time()

            # Chống lặp cảnh báo: cùng IP + cùng loại tấn công trong khoảng cooldown thì bỏ qua.
            # Nhờ vậy khi người dùng dừng tấn công, hệ thống không tiếp tục báo liên tục.
            last_time = self._last_alerts.get((src_ip, attack_type), 0.0)
            if self.cooldown_seconds > 0 and now - last_time < self.cooldown_seconds:
                logger.debug(
                    "Bỏ qua cảnh báo trùng cho %s/%s (cooldown còn %.1fs).",
                    src_ip,
                    attack_type,
                    self.cooldown_seconds - (now - last_time),
                )
                return None
            self._last_alerts[(src_ip, attack_type)] = now

            # Dọn bớt các mục cooldown cũ để tránh phình bộ nhớ
            if len(self._last_alerts) > 1000:
                cutoff = now - max(self.cooldown_seconds, 60) * 10
                self._last_alerts = {
                    key: ts for key, ts in self._last_alerts.items() if ts >= cutoff
                }

        # 1. Ghi cảnh báo mới vào PostgreSQL
        status = "pending" if self.auto_block_enabled else "alerted"
        alert_id = add_alert(
            src_ip=src_ip,
            attack_type=attack_type,
            score=score,
            severity=severity,
            status=status,
            dest_ip=dest_ip,
            source_of_detection=source_of_detection,
            confidence=confidence,
            evidence=evidence,
            alert_timestamp=alert_timestamp,
        )
        logger.warning(
            "CẢNH BÁO SỚM [%s] - IP: %s | Loại: %s | Điểm EMA: %.4f | ID: %d (%s)",
            severity,
            src_ip,
            attack_type,
            score,
            alert_id,
            "Tự động chặn sau đếm ngược" if self.auto_block_enabled else "CHẾ ĐỘ CHỈ CẢNH BÁO",
        )

        # 2. Khởi tạo đếm ngược tự động chặn nếu được kích hoạt
        if self.auto_block_enabled:
            expire_ts = time.time() + self.countdown_seconds
            timer = threading.Timer(
                self.countdown_seconds,
                self._handle_timeout,
                args=(alert_id, src_ip, attack_type, score),
            )
            timer.daemon = True

            with self.lock:
                self.active_timers[alert_id] = {
                    "timer": timer,
                    "expire_ts": expire_ts,
                    "src_ip": src_ip,
                    "attack_type": attack_type,
                    "score": score,
                }
            timer.start()
            logger.info("Bắt đầu đếm ngược %d giây cho Cảnh báo #%d (IP: %s)", self.countdown_seconds, alert_id, src_ip)

        return alert_id

    def _handle_timeout(self, alert_id: int, src_ip: str, attack_type: str, score: float) -> None:
        """Xử lý khi hết thời gian đếm ngược mà người dùng không phản hồi."""
        with self.lock:
            if alert_id not in self.active_timers:
                return
            del self.active_timers[alert_id]

        logger.info("Hết thời gian đếm ngược cho Cảnh báo #%d. Tiến hành TỰ ĐỘNG CHẶN IP %s...", alert_id, src_ip)

        # Thực hiện chặn IP
        reason = f"Tự động chặn do phát hiện sớm tấn công {attack_type} (Điểm {score})"
        self.blocker.block_ip(ip=src_ip, reason=reason, alert_id=alert_id)

        # Cập nhật trạng thái cảnh báo
        update_alert_status(alert_id=alert_id, status="auto_blocked", decided_by="system")

    def manual_block(self, alert_id: int) -> tuple[bool, str]:
        """Người dùng nhấn nút 'Chặn' thủ công trên Dashboard."""
        alert = get_alert_by_id(alert_id)
        if not alert:
            return False, f"Không tìm thấy cảnh báo #{alert_id}"

        src_ip = alert["src_ip"]
        attack_type = alert["attack_type"]

        # Hủy timer nếu còn đang chạy
        with self.lock:
            if alert_id in self.active_timers:
                timer_info = self.active_timers.pop(alert_id)
                timer_info["timer"].cancel()

        # Tiến hành chặn
        reason = f"Quản trị viên chặn thủ công cảnh báo #{alert_id} ({attack_type})"
        success, msg = self.blocker.block_ip(ip=src_ip, reason=reason, alert_id=alert_id)

        if success:
            update_alert_status(alert_id=alert_id, status="manual_blocked", decided_by="admin")
            self._clear_cooldown(src_ip)

        return success, msg

    def ignore_alert(self, alert_id: int) -> tuple[bool, str]:
        """Người dùng nhấn nút 'Bỏ qua' trên Dashboard."""
        alert = get_alert_by_id(alert_id)
        if not alert:
            return False, f"Không tìm thấy cảnh báo #{alert_id}"

        src_ip = alert["src_ip"]

        # Hủy timer nếu còn đang chạy
        with self.lock:
            if alert_id in self.active_timers:
                timer_info = self.active_timers.pop(alert_id)
                timer_info["timer"].cancel()

        # Cập nhật DB
        update_alert_status(alert_id=alert_id, status="ignored", decided_by="admin")

        # Đặt lại điểm số tích lũy của IP này về 0
        self.scorer.reset_score(src_ip)
        self._clear_cooldown(src_ip)
        logger.info("Quản trị viên đã bỏ qua cảnh báo #%d và đặt lại điểm số cho IP %s.", alert_id, src_ip)

        return True, f"Đã bỏ qua cảnh báo #{alert_id}"

    def _clear_cooldown(self, src_ip: str) -> None:
        """Xoá bộ đếm cooldown của một IP để cuộc tấn công mới được cảnh báo ngay."""
        with self.lock:
            for key in [k for k in self._last_alerts if k[0] == src_ip]:
                del self._last_alerts[key]

    def get_remaining_seconds(self, alert_id: int) -> float:
        """Lấy số giây đếm ngược còn lại của một cảnh báo."""
        with self.lock:
            if alert_id in self.active_timers:
                remaining = self.active_timers[alert_id]["expire_ts"] - time.time()
                return max(0.0, round(remaining, 1))
            return 0.0

    def get_active_countdowns(self) -> dict[int, float]:
        """Lấy danh sách tất cả các cảnh báo đang đếm ngược kèm số giây còn lại."""
        now = time.time()
        with self.lock:
            return {
                aid: max(0.0, round(data["expire_ts"] - now, 1))
                for aid, data in self.active_timers.items()
            }
