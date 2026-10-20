"""
Module ngăn chặn và gỡ chặn IP tự động qua tường lửa UFW (Blocker).
Kiểm tra tính hợp lệ của IP bằng thư viện ipaddress, kiểm tra whitelist,
chỉ gọi lệnh ufw bằng sudo giới hạn, tự động ghi nhận vào CSDL.
"""

from __future__ import annotations

import ipaddress
import logging
import platform
import subprocess
import threading
from typing import Tuple

from src.db import (
    add_blocked_ip,
    is_in_whitelist,
    is_ip_blocked,
    unblock_ip_record,
)

logger = logging.getLogger("AI_IDS.Blocker")


class IPBlocker:
    """
    Quản lý việc tương tác với tường lửa ufw để chặn/gỡ chặn IP nguồn nguy hiểm.
    """

    def __init__(
        self,
        block_cmd_prefix: str = "sudo ufw insert 1 deny from",
        unblock_cmd_prefix: str = "sudo ufw delete deny from",
        default_duration_minutes: int = 60,
    ):
        self.block_cmd_prefix = block_cmd_prefix
        self.unblock_cmd_prefix = unblock_cmd_prefix
        self.default_duration_minutes = default_duration_minutes
        self.lock = threading.Lock()
        self.is_linux = platform.system().lower() == "linux"

    def is_valid_ip(self, ip_str: str) -> bool:
        """Kiểm tra chuỗi có phải địa chỉ IPv4/IPv6 hợp lệ không."""
        try:
            ipaddress.ip_address(ip_str.strip())
            return True
        except ValueError:
            return False

    def block_ip(
        self,
        ip: str,
        reason: str,
        alert_id: int | None = None,
        duration_minutes: int | None = None,
    ) -> Tuple[bool, str]:
        """
        Thực hiện chặn IP:
        1. Kiểm tra tính hợp lệ của IP.
        2. Kiểm tra IP trong danh sách whitelist.
        3. Kiểm tra nếu đã bị chặn.
        4. Gọi lệnh ufw và lưu DB.

        Trả về:
            tuple (success: bool, message: str)
        """
        clean_ip = ip.strip()

        # 1. Kiểm tra IP hợp lệ
        if not self.is_valid_ip(clean_ip):
            msg = f"Địa chỉ IP không hợp lệ: '{clean_ip}'"
            logger.warning(msg)
            return False, msg

        # 2. Kiểm tra Whitelist
        if is_in_whitelist(clean_ip):
            msg = f"IP {clean_ip} nằm trong Whitelist! Từ chối chặn."
            logger.warning(msg)
            return False, msg

        # 3. Kiểm tra xem đã chặn chưa
        if is_ip_blocked(clean_ip):
            msg = f"IP {clean_ip} đã đang trong danh sách bị chặn."
            logger.info(msg)
            return True, msg

        duration = duration_minutes or self.default_duration_minutes
        method = "ufw"

        with self.lock:
            # 4. Thực thi lệnh tường lửa trên Linux
            if self.is_linux:
                cmd = f"{self.block_cmd_prefix} {clean_ip}"
                try:
                    logger.info("Thực thi lệnh chặn: %s", cmd)
                    result = subprocess.run(
                        cmd.split(),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode != 0:
                        logger.error("Lỗi khi chạy ufw block (code %d): %s", result.returncode, result.stderr)
                        # Vẫn có thể lưu trạng thái giả lập nếu lỗi quyền hạn trong lab
                        method = "ufw_failed"
                    else:
                        logger.info("Đã chặn thành công IP %s bằng UFW.", clean_ip)
                except Exception as ex:
                    logger.error("Ngoại lệ khi gọi subprocess ufw: %s", ex)
                    method = "error"
            else:
                # Chế độ mô phỏng cho môi trường phát triển / Windows
                logger.warning("Hệ điều hành %s không hỗ trợ UFW trực tiếp. Ghi nhận chặn dạng mô phỏng (simulated).", platform.system())
                method = "simulated"

            # Lưu vào CSDL
            add_blocked_ip(
                ip=clean_ip,
                reason=reason,
                alert_id=alert_id,
                duration_minutes=duration,
                method=method,
            )

        return True, f"Đã chặn IP {clean_ip} ({method})"

    def unblock_ip(self, ip: str) -> Tuple[bool, str]:
        """
        Thực hiện gỡ chặn IP qua ufw và cập nhật CSDL.

        Trả về:
            tuple (success: bool, message: str)
        """
        clean_ip = ip.strip()
        if not self.is_valid_ip(clean_ip):
            return False, f"Địa chỉ IP không hợp lệ: '{clean_ip}'"

        with self.lock:
            if self.is_linux:
                cmd = f"{self.unblock_cmd_prefix} {clean_ip}"
                try:
                    logger.info("Thực thi lệnh gỡ chặn: %s", cmd)
                    result = subprocess.run(
                        cmd.split(),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if result.returncode != 0:
                        logger.warning("Lỗi khi chạy ufw unblock: %s", result.stderr)
                except Exception as ex:
                    logger.error("Ngoại lệ khi gỡ chặn IP %s: %s", clean_ip, ex)

            # Cập nhật unblocked_at trong DB
            unblock_ip_record(clean_ip)
            logger.info("Đã cập nhật gỡ chặn IP %s trong CSDL.", clean_ip)

        return True, f"Đã gỡ chặn IP {clean_ip}"
