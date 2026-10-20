"""
Module tính điểm phát hiện sớm (Early Detection Scorer).
Sử dụng công thức làm mịn số mũ tích lũy (Exponential Moving Average):
S_t = alpha * S_(t-1) + (1 - alpha) * p_t
trong đó p_t là xác suất tấn công (1 - P(normal)) do mô hình AI dự đoán ở bước t.
"""

from __future__ import annotations

import threading
from typing import Tuple


class EarlyDetectionScorer:
    """
    Quản lý điểm bất thường tích lũy theo từng IP nguồn.
    Cảnh báo phát hiện sớm trước khi cuộc tấn công hoàn tất.
    """

    def __init__(
        self,
        alpha: float = 0.7,
        theta: float = 0.7,
        high_threshold: float = 0.9,
        fast_detection: bool = False,
    ):
        """
        Khởi tạo scorer:
        - alpha: Trọng số của điểm lịch sử S_(t-1)
        - theta: Ngưỡng kích hoạt cảnh báo phát hiện sớm
        - high_threshold: Ngưỡng phân loại mức độ cảnh báo 'Cao'
        - fast_detection: Kích hoạt cảnh báo ngay lập tức khi phát hiện hành vi tấn công rõ rệt (p_t >= 0.85)
        """
        self.alpha = float(alpha)
        self.theta = float(theta)
        self.high_threshold = float(high_threshold)
        self.fast_detection = bool(fast_detection)

        # Lưu điểm S_t theo từng IP nguồn: src_ip -> float
        self.scores: dict[str, float] = {}
        self.lock = threading.Lock()

    def update_score(self, src_ip: str, p_t: float) -> Tuple[float, str | None, bool]:
        """
        Cập nhật điểm tích lũy sau mỗi sự kiện mới của IP nguồn.
        Nếu bật fast_detection và p_t >= 0.85, điểm lập tức nhảy vọt để cảnh báo ngay tức thì.
        """
        # Giới hạn p_t trong đoạn [0.0, 1.0]
        p_t = max(0.0, min(1.0, float(p_t)))

        with self.lock:
            prev_score = self.scores.get(src_ip, 0.0)
            
            # Chế độ phát hiện siêu tốc: Nếu dấu hiệu tấn công rõ ràng (p_t >= 0.85), cảnh báo ngay lập tức
            if self.fast_detection and p_t >= 0.85:
                current_score = max(p_t, self.alpha * prev_score + (1.0 - self.alpha) * p_t)
            else:
                # Công thức làm mịn EMA tiêu chuẩn
                current_score = self.alpha * prev_score + (1.0 - self.alpha) * p_t
                
            # Làm tròn 4 chữ số thập phân để đảm bảo độ chính xác
            current_score = round(current_score, 4)
            self.scores[src_ip] = current_score

        is_alert = current_score >= self.theta
        severity: str | None = None

        if is_alert:
            if current_score >= self.high_threshold:
                severity = "Cao"
            else:
                severity = "Trung bình"

        return current_score, severity, is_alert

    def get_score(self, src_ip: str) -> float:
        """Lấy điểm số hiện tại của một IP nguồn."""
        with self.lock:
            return self.scores.get(src_ip, 0.0)

    def reset_score(self, src_ip: str) -> None:
        """Đặt lại điểm số về 0 sau khi xử lý hoặc bỏ qua."""
        with self.lock:
            if src_ip in self.scores:
                self.scores[src_ip] = 0.0

    def update_parameters(
        self,
        alpha: float | None = None,
        theta: float | None = None,
        high_threshold: float | None = None,
    ) -> None:
        """Cập nhật các tham số cấu hình động."""
        with self.lock:
            if alpha is not None:
                self.alpha = float(alpha)
            if theta is not None:
                self.theta = float(theta)
            if high_threshold is not None:
                self.high_threshold = float(high_threshold)
