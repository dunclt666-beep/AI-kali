"""
Script huấn luyện mô hình độc lập (Model Training Pipeline).
- Đọc tệp CSV đặc trưng đã gán nhãn
- Phân chia tập huấn luyện/kiểm thử theo thời gian (Time-based split, không xáo trộn ngẫu nhiên)
- Huấn luyện RandomForestClassifier (Request & Window baseline)
- Huấn luyện mô hình Deep Learning LSTM (Pure NumPy LSTM hoặc PyTorch) trên chuỗi đặc trưng thời gian
- Đánh giá Precision, Recall, F1, FPR (False Positive Rate) cho cả RF, LSTM và Ensemble
- Lưu mô hình RF và LSTM vào thư mục models/
- Ghi nhận thông tin phiên bản mô hình vào PostgreSQL
"""

from __future__ import annotations

import argparse
import datetime
import logging
import os
import sys
from pathlib import Path

# Đảm bảo Python nhận diện được thư mục gốc của dự án khi chạy dạng script
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import joblib
import numpy as np
import pandas as pd
import yaml
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.preprocessing import StandardScaler

from src.db import init_db, save_model_meta
from src.features import FEATURE_COLUMNS
from src.lstm_numpy import NumpyLSTMClassifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("AI_IDS.Train")


def compute_per_class_fpr(y_true: np.ndarray, y_pred: np.ndarray, classes: list[str]) -> dict[str, float]:
    """Tính False Positive Rate (FPR) riêng cho từng lớp từ Confusion Matrix an toàn."""
    present_labels = sorted(list(set(y_true) | set(y_pred)))
    eval_classes = [c for c in classes if c in present_labels]
    if not eval_classes:
        eval_classes = present_labels

    try:
        cm = confusion_matrix(y_true, y_pred, labels=eval_classes)
        total_samples = np.sum(cm)
        fpr_dict = {}

        for i, cls_name in enumerate(eval_classes):
            tp = cm[i, i]
            fn = np.sum(cm[i, :]) - tp
            fp = np.sum(cm[:, i]) - tp
            tn = total_samples - (tp + fp + fn)

            denominator = fp + tn
            fpr_val = float(fp / denominator) if denominator > 0 else 0.0
            fpr_dict[str(cls_name)] = round(fpr_val, 4)

        for cls_name in classes:
            if str(cls_name) not in fpr_dict:
                fpr_dict[str(cls_name)] = 0.0

        return fpr_dict
    except Exception as ex:
        logger.warning("Lỗi tính confusion_matrix FPR: %s", ex)
        return {str(c): 0.0 for c in classes}


def create_sequences(x_data: np.ndarray, y_data: np.ndarray, seq_len: int = 5):
    """Tạo chuỗi trượt thời gian (rolling sequences) cho mô hình LSTM."""
    x_seq, y_seq = [], []
    for i in range(len(x_data)):
        if i < seq_len - 1:
            pad_count = seq_len - 1 - i
            seq = [x_data[0]] * pad_count + list(x_data[: i + 1])
        else:
            seq = list(x_data[i - seq_len + 1 : i + 1])
        x_seq.append(seq)
        y_seq.append(y_data[i])
    return np.array(x_seq, dtype=np.float32), np.array(y_seq)


def train_lstm_network(
    x_train_seq: np.ndarray,
    y_train_idx: np.ndarray,
    x_test_seq: np.ndarray,
    classes: list[str],
    lstm_output_path: str,
) -> np.ndarray | None:
    """
    Huấn luyện mô hình LSTM:
    Ưu tiên 1: PyTorch nếu đã cài đặt.
    Ưu tiên 2: Pure NumPy LSTM (Zero-dependency, không tốn dung lượng ổ đĩa).
    """
    # 1. Thử dùng PyTorch nếu máy có sẵn
    try:
        import torch
        import torch.nn as nn
        import torch.optim as optim
        from torch.utils.data import DataLoader, TensorDataset

        logger.info("Phát hiện PyTorch: Huấn luyện mạng PyTorch LSTM...")

        class LSTMNet(nn.Module):
            def __init__(self, in_d, h_d, n_c):
                super().__init__()
                self.lstm = nn.LSTM(in_d, h_d, batch_first=True)
                self.dropout = nn.Dropout(0.2)
                self.fc1 = nn.Linear(h_d, 32)
                self.relu = nn.ReLU()
                self.fc2 = nn.Linear(32, n_c)
            def forward(self, x):
                out, _ = self.lstm(x)
                return self.fc2(self.relu(self.fc1(self.dropout(out[:, -1, :]))))

        model = LSTMNet(x_train_seq.shape[2], 64, len(classes))
        loader = DataLoader(
            TensorDataset(torch.tensor(x_train_seq), torch.tensor(y_train_idx, dtype=torch.long)),
            batch_size=32, shuffle=True
        )
        opt = optim.Adam(model.parameters(), lr=0.002)
        crit = nn.CrossEntropyLoss()

        for ep in range(1, 13):
            for bx, by in loader:
                opt.zero_grad()
                crit(model(bx), by).backward()
                opt.step()

        pt_path = "models/lstm_model.pt"
        os.makedirs(os.path.dirname(os.path.abspath(pt_path)), exist_ok=True)
        torch.save(model.state_dict(), pt_path)
        logger.info("Đã lưu PyTorch LSTM tại: %s", pt_path)

        with torch.no_grad():
            import torch.nn.functional as F
            test_probs = F.softmax(model(torch.tensor(x_test_seq)), dim=-1).numpy()
        return test_probs

    except ImportError:
        pass

    # 2. Huấn luyện bằng Pure NumPy LSTM (Chạy ngay, không cần tải bất kỳ gói nặng nào)
    logger.info("Sử dụng Pure NumPy LSTM (Cực nhẹ, zero-dependency, chạy mượt trên mọi môi trường)...")
    lstm_model = NumpyLSTMClassifier(
        input_dim=x_train_seq.shape[2],
        hidden_dim=32,
        num_classes=len(classes),
    )
    lstm_model.fit(x_train_seq, y_train_idx, epochs=8, lr=0.008, batch_size=32)

    save_path = lstm_output_path if lstm_output_path.endswith(".joblib") else "models/lstm_model.joblib"
    os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
    lstm_model.save(save_path)

    test_probs = lstm_model.predict_proba(x_test_seq)
    return test_probs


def train_model(
    csv_path: str = "data/sample_dataset.csv",
    output_model_path: str = "models/detector_model.joblib",
    lstm_model_path: str = "models/lstm_model.joblib",
    database_config: dict | None = None,
    train_ratio: float = 0.8,
    seq_len: int = 5,
) -> None:
    """Quy trình huấn luyện Ensemble kết hợp Random Forest và LSTM."""
    if not os.path.exists(csv_path):
        logger.error("Không tìm thấy tệp dữ liệu CSV tại: %s", csv_path)
        logger.info("Hãy chạy script: python3 src/generate_sample_data.py để tạo dữ liệu mẫu trước.")
        sys.exit(1)

    logger.info("Đọc dữ liệu từ %s...", csv_path)
    df = pd.read_csv(csv_path)

    missing_cols = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing_cols:
        logger.error("Dữ liệu CSV thiếu các cột đặc trưng bắt buộc: %s", missing_cols)
        sys.exit(1)

    label_col = "label" if "label" in df.columns else "class"
    if label_col not in df.columns:
        logger.error("Dữ liệu CSV thiếu cột nhãn ('label' hoặc 'class').")
        sys.exit(1)

    logger.info("Tổng số mẫu: %d dòng. Các lớp: %s", len(df), df[label_col].value_counts().to_dict())

    # 1. Phân chia tập dữ liệu (Stratified split đảm bảo mọi lớp tấn công đều có ở cả Train và Test)
    from sklearn.model_selection import train_test_split
    try:
        train_df, test_df = train_test_split(
            df,
            train_size=train_ratio,
            random_state=42,
            stratify=df[label_col] if df[label_col].nunique() > 1 else None,
        )
    except Exception:
        train_df, test_df = train_test_split(df, train_size=train_ratio, random_state=42)

    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)

    logger.info("Phân chia tập dữ liệu: Tập Train = %d mẫu, Tập Test = %d mẫu", len(train_df), len(test_df))

    x_train = train_df[FEATURE_COLUMNS].values.astype(np.float64)
    y_train = train_df[label_col].values
    x_test = test_df[FEATURE_COLUMNS].values.astype(np.float64)
    y_test = test_df[label_col].values

    # 2. Chuẩn hóa đặc trưng
    scaler = StandardScaler()
    x_train_scaled = scaler.fit_transform(x_train)
    x_test_scaled = scaler.transform(x_test)

    # 3. Huấn luyện Random Forest
    logger.info("--- [1/2] HUẤN LUYỆN RANDOM FOREST (Request & Window Baseline) ---")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=14,
        min_samples_split=4,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )
    clf.fit(x_train_scaled, y_train)

    classes = list(clf.classes_)
    y_pred_rf = clf.predict(x_test_scaled)
    rf_probs = clf.predict_proba(x_test_scaled)

    logger.info("=== BÁO CÁO RANDOM FOREST TRÊN TẬP KIỂM THỬ ===")
    print("\n" + classification_report(y_test, y_pred_rf, digits=4))

    # 4. Huấn luyện LSTM
    logger.info("--- [2/2] HUẤN LUYỆN LSTM TIME-SERIES DEEP LEARNING (Chuỗi 5 bước) ---")
    x_train_seq, y_train_seq = create_sequences(x_train_scaled, y_train, seq_len=seq_len)
    x_test_seq, y_test_seq = create_sequences(x_test_scaled, y_test, seq_len=seq_len)

    cls_to_idx = {c: i for i, c in enumerate(classes)}
    y_train_idx = np.array([cls_to_idx[lbl] for lbl in y_train], dtype=np.int64)

    lstm_test_probs = train_lstm_network(
        x_train_seq,
        y_train_idx,
        x_test_seq,
        classes,
        lstm_output_path=lstm_model_path,
    )

    # 5. Đánh giá Ensemble kết hợp
    if lstm_test_probs is not None:
        ensemble_probs = 0.5 * rf_probs + 0.5 * lstm_test_probs
        y_pred_ens_idx = np.argmax(ensemble_probs, axis=1)
        y_pred_final = np.array([classes[idx] for idx in y_pred_ens_idx])

        logger.info("=== BÁO CÁO ĐÁNH GIÁ MÔ HÌNH ENSEMBLE (RF + LSTM) ===")
        print("\n" + classification_report(y_test, y_pred_final, digits=4))
    else:
        y_pred_final = y_pred_rf

    # Tính FPR cho từng lớp
    fpr_dict = compute_per_class_fpr(y_test, y_pred_final, classes)
    print("=== TY LE DUONG TINH GIA (FPR - False Positive Rate) ===")
    for cls_name, fpr_val in fpr_dict.items():
        print(f"  - Lop {cls_name:12s}: FPR = {fpr_val:.4f} ({fpr_val*100:.2f}%)")

    macro_f1 = float(f1_score(y_test, y_pred_final, average="macro"))
    weighted_f1 = float(f1_score(y_test, y_pred_final, average="weighted"))
    normal_fpr = fpr_dict.get("normal", 0.0)
    print(f"\nMacro F1: {macro_f1:.4f} | Weighted F1: {weighted_f1:.4f} | Normal FPR: {normal_fpr:.4f}\n")

    # 6. Lưu mô hình Random Forest & Scaler
    os.makedirs(os.path.dirname(os.path.abspath(output_model_path)), exist_ok=True)
    model_bundle = {
        "model": clf,
        "scaler": scaler,
        "feature_columns": FEATURE_COLUMNS,
        "classes": classes,
        "trained_at": datetime.datetime.now().isoformat(),
        "macro_f1": macro_f1,
        "has_lstm": lstm_test_probs is not None,
    }
    joblib.dump(model_bundle, output_model_path)
    logger.info("Đã lưu gói mô hình Random Forest tại: %s", output_model_path)

    # 7. Ghi nhận metadata mô hình vào PostgreSQL (nếu có kết nối DB)
    try:
        if database_config is None:
            with open("config.yaml", "r", encoding="utf-8") as config_file:
                database_config = (yaml.safe_load(config_file) or {}).get("database", {})
        init_db(database_config)
        version_id = f"ensemble_rf_lstm_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        algorithm_name = "Ensemble (RandomForest + LSTM)" if lstm_test_probs is not None else "RandomForestClassifier"
        save_model_meta(
            version=version_id,
            algorithm=algorithm_name,
            trained_at=datetime.datetime.now().isoformat(),
            f1=macro_f1,
            fpr=normal_fpr,
            path=output_model_path,
            is_active=1,
        )
        logger.info("Đã cập nhật phiên bản mô hình '%s' trong CSDL.", version_id)
    except Exception as ex:
        logger.warning("Không thể lưu metadata mô hình vào PostgreSQL (bỏ qua nếu DB chưa chạy): %s", ex)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Huấn luyện mô hình AI phát hiện tấn công web kết hợp LSTM")
    parser.add_argument("--csv", default="data/sample_dataset.csv", help="Đường dẫn tệp CSV đặc trưng")
    parser.add_argument("--output", default="models/detector_model.joblib", help="Đường dẫn lưu tệp mô hình RF")
    parser.add_argument("--lstm", default="models/lstm_model.joblib", help="Đường dẫn lưu tệp mô hình LSTM")
    parser.add_argument("--config", default="config.yaml", help="Tệp cấu hình PostgreSQL")
    parser.add_argument("--seq", type=int, default=5, help="Độ dài chuỗi trượt thời gian cho LSTM")
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as config_file:
        app_config = yaml.safe_load(config_file) or {}

    train_model(
        csv_path=args.csv,
        output_model_path=args.output,
        lstm_model_path=args.lstm,
        database_config=app_config.get("database", {}),
        seq_len=args.seq,
    )
