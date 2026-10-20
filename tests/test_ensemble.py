"""
Unit tests kiểm thử mô hình Ensemble và Pure NumPy LSTM.
"""

from __future__ import annotations

import numpy as np
import pytest

from src.features import SlidingWindowTracker
from src.lstm_numpy import NumpyLSTMClassifier
from src.model import AttackClassifier


def test_numpy_lstm_forward_and_fit():
    # Kiểm tra LSTM thuần bằng NumPy
    model = NumpyLSTMClassifier(input_dim=19, hidden_dim=16, num_classes=5)

    # Dữ liệu giả lập 10 chuỗi
    X_dummy = np.random.randn(10, 5, 19).astype(np.float32)
    y_dummy = np.random.randint(0, 5, size=(10,))

    # Huấn luyện thử 2 epoch
    model.fit(X_dummy, y_dummy, epochs=2, batch_size=4)

    # Dự đoán
    probs = model.predict_proba(X_dummy)
    assert probs.shape == (10, 5)
    # Tổng xác suất mỗi hàng xấp xỉ 1
    assert np.allclose(np.sum(probs, axis=1), 1.0, atol=1e-5)


def test_sliding_window_sequence_extraction():
    tracker = SlidingWindowTracker(window_size_n=10)
    src_ip = "192.168.1.99"

    seq_empty = tracker.get_feature_sequence(src_ip, seq_len=5)
    assert len(seq_empty) == 5
    assert len(seq_empty[0]) == 19

    for i in range(2):
        event = {
            "timestamp": f"2026-10-12T12:00:0{i}Z",
            "event_type": "http",
            "src_ip": src_ip,
            "http": {"http_method": "GET", "url": f"/item/{i}", "status": 200},
        }
        tracker.get_full_feature_vector(event)

    seq_padded = tracker.get_feature_sequence(src_ip, seq_len=5)
    assert len(seq_padded) == 5
    for step in seq_padded:
        assert len(step) == 19


def test_ensemble_classifier_fallback():
    clf = AttackClassifier(rf_model_path="models/non_existent.joblib")
    features = {
        "sql_keyword_count": 2.0,
        "url_length": 80.0,
        "special_char_count": 5.0,
    }
    pred, probs, attack_prob = clf.predict(features)
    assert pred == "sqli"
    assert attack_prob > 0.8
    assert "sqli" in probs
