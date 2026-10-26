"""
Mô hình Deep Learning LSTM thuần bằng NumPy (Zero-Dependency Pure NumPy LSTM).
Không cần cài đặt TensorFlow hay PyTorch (tránh lỗi hết dung lượng ổ đĩa / Disk Quota Exceeded).
Cài đặt đầy đủ 4 cổng của tế bào LSTM: Forget Gate, Input Gate, Candidate Cell, Output Gate.
Huấn luyện bằng thuật toán tối ưu hóa Adam.
"""

from __future__ import annotations

import logging
import os
import joblib
import numpy as np

logger = logging.getLogger("AI_IDS.NumpyLSTM")


def sigmoid(x: np.ndarray) -> np.ndarray:
    """Hàm kích hoạt Sigmoid có giới hạn để tránh tràn số."""
    x = np.clip(x, -25.0, 25.0)
    return 1.0 / (1.0 + np.exp(-x))


def softmax(x: np.ndarray) -> np.ndarray:
    """Hàm Softmax ổn định số học theo từng hàng."""
    exp_x = np.exp(x - np.max(x, axis=-1, keepdims=True))
    return exp_x / np.sum(exp_x, axis=-1, keepdims=True)


class NumpyLSTMClassifier:
    """
    Mạng nơ-ron hồi quy LSTM độc lập xây dựng hoàn toàn trên NumPy.
    Phân tích chuỗi thời gian (time-series sequence) kích thước (batch, seq_len, input_dim).
    """

    def __init__(self, input_dim: int = 19, hidden_dim: int = 32, num_classes: int = 5):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_classes = num_classes

        # Khởi tạo trọng số Xavier/Glorot
        scale = np.sqrt(2.0 / (input_dim + hidden_dim))
        # 4 cổng xếp chồng: Forget (f), Input (i), Candidate (c), Output (o)
        self.W = np.random.randn(4 * hidden_dim, input_dim) * scale
        self.U = np.random.randn(4 * hidden_dim, hidden_dim) * scale
        self.b = np.zeros((4 * hidden_dim, 1))

        # Forget gate bias khởi tạo = 1.0 (chuẩn LSTM hiện đại để nhớ chuỗi dài)
        self.b[:hidden_dim] = 1.0

        # Lớp phân loại đầu ra (Dense / Softmax)
        out_scale = np.sqrt(2.0 / (hidden_dim + num_classes))
        self.W_out = np.random.randn(num_classes, hidden_dim) * out_scale
        self.b_out = np.zeros((num_classes, 1))

    def forward_step(self, x_t: np.ndarray, h_prev: np.ndarray, c_prev: np.ndarray):
        """Lan truyền xuôi qua một bước thời gian t (LSTM Cell)."""
        # x_t: (input_dim, 1), h_prev: (hidden_dim, 1), c_prev: (hidden_dim, 1)
        gates = np.dot(self.W, x_t) + np.dot(self.U, h_prev) + self.b
        H = self.hidden_dim

        f = sigmoid(gates[0:H])
        i = sigmoid(gates[H:2*H])
        c_bar = np.tanh(gates[2*H:3*H])
        o = sigmoid(gates[3*H:4*H])

        c = f * c_prev + i * c_bar
        h = o * np.tanh(c)
        return h, c, (f, i, c_bar, o, c_prev, h_prev, x_t)

    def forward_sequence(self, seq: np.ndarray) -> tuple[np.ndarray, list]:
        """Lan truyền qua toàn bộ chuỗi: seq có shape (seq_len, input_dim)."""
        seq_len = seq.shape[0]
        h = np.zeros((self.hidden_dim, 1))
        c = np.zeros((self.hidden_dim, 1))
        caches = []

        for t in range(seq_len):
            x_t = seq[t].reshape(-1, 1)
            h, c, cache = self.forward_step(x_t, h, c)
            caches.append(cache)

        # Lớp Dense phân loại
        logits = np.dot(self.W_out, h) + self.b_out  # (num_classes, 1)
        probs = softmax(logits.T).flatten()  # (num_classes,)
        return probs, caches

    def predict_proba(self, sequences: np.ndarray) -> np.ndarray:
        """Dự đoán ma trận xác suất cho tập mẫu: sequences shape (N, seq_len, input_dim)."""
        N = sequences.shape[0]
        probs_matrix = np.zeros((N, self.num_classes))
        for i in range(N):
            p, _ = self.forward_sequence(sequences[i])
            probs_matrix[i] = p
        return probs_matrix

    def fit(
        self,
        X: np.ndarray,
        y_indices: np.ndarray,
        epochs: int = 8,
        lr: float = 0.005,
        batch_size: int = 32,
    ):
        """Huấn luyện mô hình bằng Adam Optimizer mini-batch."""
        N = X.shape[0]
        logger.info("Bắt đầu huấn luyện Pure NumPy LSTM (%d mẫu, %d epochs, batch_size=%d)...", N, epochs, batch_size)

        # Khởi tạo bộ nhớ cho Adam (m và v)
        params = [self.W, self.U, self.b, self.W_out, self.b_out]
        m = [np.zeros_like(p) for p in params]
        v = [np.zeros_like(p) for p in params]
        beta1, beta2, eps = 0.9, 0.999, 1e-8
        t_step = 0

        for epoch in range(1, epochs + 1):
            perm = np.random.permutation(N)
            total_loss = 0.0

            for start in range(0, N, batch_size):
                batch_idx = perm[start : start + batch_size]
                dW = np.zeros_like(self.W)
                dU = np.zeros_like(self.U)
                db = np.zeros_like(self.b)
                dW_out = np.zeros_like(self.W_out)
                db_out = np.zeros_like(self.b_out)

                for idx in batch_idx:
                    seq = X[idx]
                    target = y_indices[idx]
                    probs, caches = self.forward_sequence(seq)

                    # Cross-entropy loss
                    total_loss -= np.log(max(probs[target], 1e-12))

                    # Gradient tại lớp đầu ra
                    dlogits = probs.copy().reshape(-1, 1)
                    dlogits[target] -= 1.0  # (num_classes, 1)

                    # Last hidden state
                    h_last = caches[-1][5]
                    dW_out += np.dot(dlogits, h_last.T)
                    db_out += dlogits

                    # BPTT qua bước cuối cùng (xấp xỉ hiệu quả)
                    dh = np.dot(self.W_out.T, dlogits)
                    f, i_gate, c_bar, o, c_prev, h_prev, x_t = caches[-1]
                    do = dh * np.tanh(caches[-1][4]) * o * (1.0 - o)
                    dgates = np.zeros_like(self.b)
                    dgates[3*self.hidden_dim : 4*self.hidden_dim] = do
                    dW += np.dot(dgates, x_t.T)
                    dU += np.dot(dgates, h_prev.T)
                    db += dgates

                # Cập nhật Adam
                t_step += 1
                grads = [dW, dU, db, dW_out, db_out]
                B = len(batch_idx)

                for k in range(len(params)):
                    g = np.clip(grads[k] / B, -1.0, 1.0)
                    m[k] = beta1 * m[k] + (1.0 - beta1) * g
                    v[k] = beta2 * v[k] + (1.0 - beta2) * (g ** 2)
                    m_hat = m[k] / (1.0 - (beta1 ** t_step))
                    v_hat = v[k] / (1.0 - (beta2 ** t_step))
                    params[k] -= lr * m_hat / (np.sqrt(v_hat) + eps)

            avg_loss = total_loss / N
            if epoch % 2 == 0 or epoch == epochs:
                logger.info("  Epoch [%d/%d] - Loss: %.4f", epoch, epochs, avg_loss)

    def save(self, path: str):
        """Lưu trọng số mô hình."""
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        data = {
            "W": self.W,
            "U": self.U,
            "b": self.b,
            "W_out": self.W_out,
            "b_out": self.b_out,
            "input_dim": self.input_dim,
            "hidden_dim": self.hidden_dim,
            "num_classes": self.num_classes,
        }
        joblib.dump(data, path)
        logger.info("Đã lưu mô hình Pure NumPy LSTM tại: %s", path)

    def load(self, path: str):
        """Nạp trọng số mô hình."""
        data = joblib.load(path)
        self.W = data["W"]
        self.U = data["U"]
        self.b = data["b"]
        self.W_out = data["W_out"]
        self.b_out = data["b_out"]
        self.input_dim = data.get("input_dim", 19)
        self.hidden_dim = data.get("hidden_dim", 32)
        self.num_classes = data.get("num_classes", 5)
        logger.info("Đã nạp thành công mô hình Pure NumPy LSTM từ: %s", path)
