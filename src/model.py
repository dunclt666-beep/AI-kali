"""
Module quản lý mô hình học máy kết hợp Ensemble: Random Forest + LSTM.
Hỗ trợ cả:
1. Pure NumPy LSTM (Zero-dependency, cực nhẹ, không lo hết dung lượng ổ đĩa)
2. PyTorch LSTM (nếu máy có cài torch)
3. TensorFlow / Keras LSTM (nếu có)
Tự động phát hiện mô hình có sẵn và kết hợp Ensemble với Random Forest.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import joblib
import numpy as np

from src.features import FEATURE_COLUMNS
from src.lstm_numpy import NumpyLSTMClassifier

logger = logging.getLogger("AI_IDS.Model")

CLASS_NAMES = ["normal", "scan", "sqli", "bruteforce", "dos"]


class AttackClassifier:
    """
    Bộ phân loại tấn công web Ensemble kết hợp Random Forest và LSTM.
    """

    def __init__(
        self,
        rf_model_path: str = "models/detector_model.joblib",
        lstm_model_path: str = "models/lstm_model.joblib",
        weight_rf: float = 0.5,
        weight_lstm: float = 0.5,
        seq_len: int = 5,
        model_path: str | None = None,  # alias tương thích ngược với bản cũ
    ):
        # Tương thích ngược: main.py bản cũ gọi AttackClassifier(model_path=...)
        if model_path is not None:
            rf_model_path = model_path
        self.rf_model_path = rf_model_path
        self.lstm_model_path = lstm_model_path
        self.weight_rf = weight_rf
        self.weight_lstm = weight_lstm
        self.seq_len = seq_len

        self.rf_model = None
        self.scaler = None
        self.lstm_model = None
        self.feature_columns: list[str] = FEATURE_COLUMNS
        self.classes: list[str] = CLASS_NAMES

        self.is_rf_loaded: bool = False
        self.is_lstm_loaded: bool = False
        self.is_loaded: bool = False

        self.load_models()

    def load_models(self) -> None:
        """Nạp cả mô hình Random Forest và LSTM từ đĩa."""
        self._load_rf(self.rf_model_path)
        self._load_lstm(self.lstm_model_path)
        self.is_loaded = self.is_rf_loaded or self.is_lstm_loaded

    def _load_rf(self, path: str) -> bool:
        if not os.path.exists(path):
            logger.warning("Không tìm thấy mô hình Random Forest tại %s", path)
            self.is_rf_loaded = False
            return False
        try:
            bundle = joblib.load(path)
            if isinstance(bundle, dict):
                self.rf_model = bundle.get("model")
                self.scaler = bundle.get("scaler")
                self.feature_columns = bundle.get("feature_columns", FEATURE_COLUMNS)
                self.classes = list(bundle.get("classes", CLASS_NAMES))
            else:
                self.rf_model = bundle
                self.scaler = None
                self.feature_columns = FEATURE_COLUMNS
                self.classes = list(getattr(self.rf_model, "classes_", CLASS_NAMES))
            self.is_rf_loaded = True
            logger.info("Đã nạp thành công mô hình Random Forest từ %s", path)
            return True
        except Exception as ex:
            logger.error("Lỗi khi nạp mô hình Random Forest: %s", ex)
            self.is_rf_loaded = False
            return False

    def _load_lstm(self, path: str) -> bool:
        # 1. Kiểm tra mô hình Pure NumPy LSTM (.joblib hoặc .npz)
        numpy_path = path if (path.endswith(".joblib") and "lstm" in path) else "models/lstm_model.joblib"
        if os.path.exists(numpy_path):
            try:
                model = NumpyLSTMClassifier(input_dim=len(self.feature_columns), num_classes=len(self.classes))
                model.load(numpy_path)
                self.lstm_model = model
                self.is_lstm_loaded = True
                logger.info("Đã nạp thành công mô hình Pure NumPy LSTM từ %s", numpy_path)
                return True
            except Exception as ex:
                logger.debug("Lỗi nạp NumPy LSTM: %s", ex)

        # 2. Kiểm tra mô hình PyTorch (.pt)
        pt_path = "models/lstm_model.pt"
        if os.path.exists(pt_path):
            try:
                import torch
                import torch.nn as nn

                class _Net(nn.Module):
                    def __init__(self, in_d, h_d, n_c):
                        super().__init__()
                        self.lstm = nn.LSTM(in_d, h_d, batch_first=True)
                        self.dropout = nn.Dropout(0.2)
                        self.fc1 = nn.Linear(h_d, 32)
                        self.relu = nn.ReLU()
                        self.fc2 = nn.Linear(32, n_c)
                    def forward(self, x):
                        out, _ = self.lstm(x)
                        out = self.dropout(out[:, -1, :])
                        return self.fc2(self.relu(self.fc1(out)))

                net = _Net(len(self.feature_columns), 64, len(self.classes))
                net.load_state_dict(torch.load(pt_path, map_location="cpu"))
                net.eval()

                class _TorchWrapper:
                    def __init__(self, n): self.n = n
                    def predict_proba(self, arr):
                        import torch.nn.functional as F
                        with torch.no_grad():
                            t = torch.tensor(arr, dtype=torch.float32)
                            return F.softmax(self.n(t), dim=-1).numpy()

                self.lstm_model = _TorchWrapper(net)
                self.is_lstm_loaded = True
                logger.info("Đã nạp thành công mô hình PyTorch LSTM từ %s", pt_path)
                return True
            except Exception as ex:
                logger.debug("Lỗi nạp PyTorch LSTM: %s", ex)

        # 3. Kiểm tra Keras (.keras)
        keras_path = "models/lstm_model.keras"
        if os.path.exists(keras_path):
            try:
                import tensorflow as tf
                self.lstm_model = tf.keras.models.load_model(keras_path)
                self.is_lstm_loaded = True
                logger.info("Đã nạp thành công mô hình Keras LSTM từ %s", keras_path)
                return True
            except Exception:
                pass

        logger.info("Chưa nạp được LSTM. Hệ thống sẽ hoạt động ở chế độ Random Forest.")
        self.is_lstm_loaded = False
        return False

    def predict(
        self,
        features_dict: dict[str, float],
        sequence_input: list[list[float]] | None = None,
    ) -> tuple[str, dict[str, float], float]:
        """
        Dự đoán lớp tấn công và xác suất bằng Ensemble RF + LSTM.
        """
        # 1. Dự đoán với Random Forest
        rf_probs: dict[str, float] = {}
        if self.is_rf_loaded and self.rf_model is not None:
            vector = [float(features_dict.get(col, 0.0)) for col in self.feature_columns]
            x_input = np.array([vector], dtype=np.float64)
            if self.scaler is not None:
                x_input = self.scaler.transform(x_input)
            probs = self.rf_model.predict_proba(x_input)[0]
            model_classes = list(getattr(self.rf_model, "classes_", self.classes))
            for cls_name, prob in zip(model_classes, probs):
                rf_probs[str(cls_name)] = float(prob)
        else:
            _, rf_probs, _ = self._heuristic_fallback(features_dict)

        # 2. Dự đoán với LSTM
        lstm_probs: dict[str, float] = {}
        if self.is_lstm_loaded and self.lstm_model is not None and sequence_input is not None:
            try:
                seq_arr = np.array([sequence_input], dtype=np.float32)  # shape: (1, seq_len, 19)
                if self.scaler is not None:
                    b, s, f = seq_arr.shape
                    seq_reshaped = seq_arr.reshape(-1, f)
                    seq_scaled = self.scaler.transform(seq_reshaped).reshape(b, s, f).astype(np.float32)
                else:
                    seq_scaled = seq_arr

                if hasattr(self.lstm_model, "predict_proba"):
                    preds = self.lstm_model.predict_proba(seq_scaled)[0]
                else:
                    preds = self.lstm_model.predict(seq_scaled, verbose=0)[0]

                for i, cls_name in enumerate(self.classes):
                    lstm_probs[cls_name] = float(preds[i]) if i < len(preds) else 0.0
            except Exception as ex:
                logger.debug("Lỗi khi dự đoán LSTM: %s", ex)
                lstm_probs = rf_probs.copy()
        else:
            lstm_probs = rf_probs.copy()

        # 3. Kết hợp Ensemble (Weighted Average)
        w_rf = self.weight_rf if self.is_lstm_loaded else 1.0
        w_lstm = self.weight_lstm if self.is_lstm_loaded else 0.0
        total_weight = w_rf + w_lstm
        w_rf /= total_weight
        w_lstm /= total_weight

        ensemble_probs: dict[str, float] = {}
        for c in CLASS_NAMES:
            p_rf = rf_probs.get(c, 0.0)
            p_lstm = lstm_probs.get(c, p_rf)
            ensemble_probs[c] = round(float(w_rf * p_rf + w_lstm * p_lstm), 4)

        predicted_class = max(ensemble_probs.keys(), key=lambda k: ensemble_probs[k])
        p_normal = ensemble_probs.get("normal", 1.0)
        attack_prob = round(1.0 - p_normal, 4)

        return predicted_class, ensemble_probs, attack_prob

    def _heuristic_fallback(self, f: dict[str, float]) -> tuple[str, dict[str, float], float]:
        """Quy tắc dự phòng nếu chưa có model nào được nạp."""
        sql_kw = f.get("sql_keyword_count", 0.0)
        ua_flag = f.get("user_agent_flag", 0.0)
        req_rate = f.get("req_rate", 0.0)
        login_fail = f.get("login_fail_count", 0.0)

        if sql_kw >= 1.0:
            pred = "sqli"
            p_attack = 0.95
        elif req_rate > 15.0 or f.get("pkts_per_sec", 0.0) > 100.0:
            pred = "dos"
            p_attack = 0.90
        elif login_fail >= 3.0:
            pred = "bruteforce"
            p_attack = 0.85
        elif ua_flag > 0.0 or f.get("unique_urls", 0.0) > 10.0:
            pred = "scan"
            p_attack = 0.80
        else:
            pred = "normal"
            p_attack = 0.05

        class_probs = {c: 0.02 for c in CLASS_NAMES}
        class_probs[pred] = p_attack
        class_probs["normal"] = round(1.0 - p_attack, 4)

        return pred, class_probs, p_attack
