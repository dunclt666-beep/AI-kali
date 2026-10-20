
# Module thu thập log từ pfSense

from __future__ import annotations

import json
import logging
import os
import posixpath
import shutil
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
    paramiko = None  # type: ignore

logger = logging.getLogger('AI_IDS.PfsenseCollector')


class PfSenseLogCollector:
    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get('enabled', False)
        self.host = config.get('host', '192.168.1.1')
        self.port = config.get('port', 22)
        self.username = config.get('username', 'root')
        self.password = config.get('password', '')
        self.sync_interval = config.get('sync_interval', 30)
        self.suricata_log_path = config.get('suricata_log_path', '/var/log/suricata/eve.json')
        self.local_log_path = config.get('local_log_path', 'data/pfsense_eve.json')
        self.method = config.get('method', 'ssh_sftp')
        # Khi bật, bỏ qua nội dung log cũ trên pfSense ở lần đồng bộ đầu tiên
        # để không phát lại các cuộc tấn công cũ (tránh cảnh báo lặp vô ích).
        self.start_from_end = bool(config.get('start_from_end', True))
        self._offset_initialized = False
        self.local_path = Path(self.local_log_path)
        self.local_path.parent.mkdir(parents=True, exist_ok=True)
        self._stop_event = threading.Event()
        self._thread = None
        self.processed_count = 0
        self.last_sync_time = None
        self.last_error = ""
        self._last_remote_lines = 0
        self.ssh = None
        self.sftp = None
        self._last_remote_offset = 0
        self._last_remote_size = 0

    def start(self):
        if not self.enabled:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self.sftp:
            try:
                self.sftp.close()
            except Exception:
                pass
            self.sftp = None
        if self.ssh:
            try:
                self.ssh.close()
            except Exception:
                pass
            self.ssh = None
        if self._thread:
            self._thread.join(timeout=5)

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def get_status(self):
        return {
            "enabled": self.enabled,
            "running": self.is_running(),
            "host": self.host,
            "method": self.method,
            "local_log": str(self.local_path),
            "remote_log": self.suricata_log_path,
            "last_sync": self.last_sync_time,
            "synced_batches": self.processed_count,
            "last_error": self.last_error,
            "has_paramiko": HAS_PARAMIKO,
        }

    def _run_loop(self):
        while not self._stop_event.is_set():
            self._sync_logs()
            self._stop_event.wait(self.sync_interval)

    def _sync_logs(self):
        if self.method == 'ssh_sftp':
            self._sync_via_ssh_sftp()
        elif self.method == 'http_webhook':
            self._sync_via_http_webhook()

    def _ensure_ssh_sftp(self):
        """Duy trì kết nối SSH/SFTP liên tục (Persistent connection) để không tốn thời gian handshake mỗi giây."""
        if not HAS_PARAMIKO:
            self.last_error = "missing paramiko: pip install paramiko"
            return False

        if self.ssh is not None and self.ssh.get_transport() and self.ssh.get_transport().is_active() and self.sftp is not None:
            return True

        # Đóng kết nối cũ nếu có
        try:
            if self.sftp:
                self.sftp.close()
        except Exception:
            pass
        try:
            if self.ssh:
                self.ssh.close()
        except Exception:
            pass
        self.sftp = None
        self.ssh = None

        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=5,
                look_for_keys=False,
                allow_agent=False,
            )
            self.sftp = self.ssh.open_sftp()
            
            # Tự dò đường dẫn log nếu cần
            try:
                resolved = self._resolve_remote_log_path(self.sftp)
                if resolved != self.suricata_log_path:
                    logger.info("Tự tìm thấy log Suricata trên pfSense: %s", resolved)
                    self.suricata_log_path = resolved
            except Exception:
                pass
            return True
        except Exception as e:
            self.last_error = f"SSH/SFTP connect failed ({self.host}:{self.port}): {e}"
            self.ssh = None
            self.sftp = None
            return False

    def _sync_via_ssh_sftp(self):
        if not self._ensure_ssh_sftp():
            return

        try:
            stat_res = self.sftp.stat(self.suricata_log_path)
            remote_size = getattr(stat_res, "st_size", 0)

            # Xử lý log xoay vòng (logrotate/truncate)
            if remote_size < self._last_remote_offset:
                logger.info("Phát hiện file log pfSense xoay vòng (kích thước giảm). Đọc lại từ đầu.")
                self._last_remote_offset = 0

            # Lần đồng bộ đầu tiên: chỉ theo dõi sự kiện mới, không phát lại log cũ
            if not self._offset_initialized:
                self._offset_initialized = True
                if self.start_from_end:
                    self._last_remote_offset = remote_size
                    logger.info(
                        "pfSense: bỏ qua %d byte log cũ, chỉ xử lý sự kiện mới.", remote_size
                    )
                    return

            # Chưa có dữ liệu mới
            if remote_size == self._last_remote_offset:
                return

            # Mở file từ xa và đọc ĐÚNG byte mới từ vị trí offset (Cực nhanh, <0.05s)
            remote_file = self.sftp.open(self.suricata_log_path, 'r')
            remote_file.seek(self._last_remote_offset)
            raw_chunk = remote_file.read()
            self._last_remote_offset = remote_size
            remote_file.close()

            if not raw_chunk:
                return

            text_chunk = raw_chunk.decode('utf-8', errors='replace')
            lines = text_chunk.splitlines()

            valid = []
            now_iso = datetime.now().isoformat()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if isinstance(event, dict):
                        event['sensor'] = 'suricata@pfsense'
                        event['sensor_host'] = self.host
                        event['sync_timestamp'] = now_iso
                        valid.append(json.dumps(event, ensure_ascii=False))
                except Exception:
                    continue

            if valid:
                self.local_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.local_path, 'a', encoding='utf-8') as out:
                    for v in valid:
                        out.write(v + '\n')

            self.processed_count += 1
            self.last_sync_time = now_iso
            self.last_error = ""
            if valid:
                logger.info("pfSense sync #%d: +%d sự kiện mới (offset: %d)", self.processed_count, len(valid), remote_size)

        except Exception as e:
            self.last_error = str(e)
            logger.error("SSH/SFTP sync lỗi: %s", e)
            # Nếu mất kết nối, reset để thử lại vòng sau
            try:
                if self.sftp: self.sftp.close()
                if self.ssh: self.ssh.close()
            except Exception:
                pass
            self.sftp = None
            self.ssh = None

    def _resolve_remote_log_path(self, sftp):
        """Ưu tiên đường dẫn cấu hình, sau đó dò eve.json theo interface Suricata."""
        configured_path = self.suricata_log_path
        try:
            sftp.stat(configured_path)
            return configured_path
        except OSError as error:
            if error.errno not in (None, 2):
                raise

        configured = PurePosixPath(configured_path)
        log_root = (
            configured.parent.parent
            if configured.parent.name.startswith("suricata_")
            else configured.parent
        )
        candidates = []
        for directory in sftp.listdir(str(log_root)):
            if not directory.startswith("suricata_"):
                continue
            candidate = posixpath.join(str(log_root), directory, "eve.json")
            try:
                stat_result = sftp.stat(candidate)
            except OSError as error:
                if error.errno in (None, 2):
                    continue
                raise
            candidates.append((getattr(stat_result, "st_mtime", 0), candidate))

        if candidates:
            return max(candidates)[1]
        raise FileNotFoundError(
            f"remote khong thay file eve.json trong thu muc: {log_root}"
        )

    def _append_new_lines(self, src_path):
        try:
            with open(src_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except Exception as e:
            self.last_error = f"doc file tam loi: {e}"
            return 0
        total = len(lines)
        start = self._last_remote_lines if total >= self._last_remote_lines else 0
        valid = []
        for line in lines[start:]:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if isinstance(event, dict):
                    event['sensor'] = 'suricata@pfsense'
                    event['sensor_host'] = self.host
                    event['sync_timestamp'] = datetime.now().isoformat()
                    valid.append(json.dumps(event, ensure_ascii=False))
            except Exception:
                continue
        if valid:
            try:
                self.local_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.local_path, 'a', encoding='utf-8') as out:
                    for v in valid:
                        out.write(v + '\n')
            except Exception as e:
                self.last_error = f"ghi file local loi: {e}"
                return 0
        self._last_remote_lines = total
        return len(valid)


    def _sync_via_http_webhook(self):
        self.last_error = "http_webhook chua ho tro, dung ssh_sftp"


class PfSenseWebhookReceiver:
    def __init__(self, host='0.0.0.0', port=5001, log_path='data/pfsense_eve.json'):
        self.host = host
        self.port = port
        self.log_path = log_path