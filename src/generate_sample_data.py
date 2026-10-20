"""
Script sinh dữ liệu mẫu giả lập cho huấn luyện và kiểm thử hệ thống.
Tạo:
1. data/sample_dataset.csv: Tập đặc trưng 19 chiều đã gán nhãn (2500 mẫu, 5 lớp cân bằng)
2. data/sample_eve.json: Luồng log Suricata EVE mẫu chuẩn JSON (gồm sự kiện http, flow, alert)
   chứa các chuỗi tấn công mẫu để kiểm thử phát hiện sớm và tự động chặn.
"""

from __future__ import annotations

import json
import os
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path
import numpy as np
import pandas as pd

# Đảm bảo Python nhận diện được thư mục gốc của dự án
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.features import FEATURE_COLUMNS


def generate_dataset_csv(
    output_path: str = "data/sample_dataset.csv",
    samples_per_class: int = 500,
) -> None:
    """Sinh tập dữ liệu bảng CSV đặc trưng đã gán nhãn cho cả 5 lớp."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    random.seed(42)
    np.random.seed(42)

    data_rows: list[dict] = []
    classes = ["normal", "scan", "sqli", "bruteforce", "dos"]

    for label in classes:
        for _ in range(samples_per_class):
            if label == "normal":
                row = {
                    "url_length": float(np.random.randint(12, 45)),
                    "special_char_count": float(np.random.choice([0, 1, 2], p=[0.7, 0.25, 0.05])),
                    "sql_keyword_count": 0.0,
                    "param_entropy": float(np.random.uniform(0.5, 2.5)),
                    "method_is_post": float(np.random.choice([0.0, 1.0], p=[0.85, 0.15])),
                    "status": float(np.random.choice([200, 302, 304], p=[0.8, 0.1, 0.1])),
                    "is_login_path": float(np.random.choice([0.0, 1.0], p=[0.95, 0.05])),
                    "user_agent_flag": 0.0,
                    "req_rate": float(np.random.uniform(0.2, 2.0)),
                    "unique_urls": float(np.random.randint(1, 5)),
                    "ratio_4xx": float(np.random.uniform(0.0, 0.05)),
                    "login_fail_count": 0.0,
                    "inter_request_time": float(np.random.uniform(1.0, 6.0)),
                    "unique_dst_ports": 1.0,
                    "short_flow_count": float(np.random.choice([0, 1], p=[0.9, 0.1])),
                    "pkts_per_sec": float(np.random.uniform(2.0, 12.0)),
                    "bytes_per_sec": float(np.random.uniform(400.0, 3000.0)),
                    "concurrent_flows": float(np.random.randint(1, 4)),
                    "suricata_alert_count": 0.0,
                }
            elif label == "sqli":
                row = {
                    "url_length": float(np.random.randint(65, 200)),
                    "special_char_count": float(np.random.randint(6, 26)),
                    "sql_keyword_count": float(np.random.randint(1, 6)),
                    "param_entropy": float(np.random.uniform(3.5, 5.8)),
                    "method_is_post": float(np.random.choice([0.0, 1.0], p=[0.6, 0.4])),
                    "status": float(np.random.choice([200, 500], p=[0.7, 0.3])),
                    "is_login_path": float(np.random.choice([0.0, 1.0], p=[0.7, 0.3])),
                    "user_agent_flag": float(np.random.choice([0.0, 1.0], p=[0.4, 0.6])),
                    "req_rate": float(np.random.uniform(1.0, 6.0)),
                    "unique_urls": float(np.random.randint(1, 4)),
                    "ratio_4xx": float(np.random.uniform(0.0, 0.2)),
                    "login_fail_count": float(np.random.choice([0, 1], p=[0.8, 0.2])),
                    "inter_request_time": float(np.random.uniform(0.3, 1.5)),
                    "unique_dst_ports": 1.0,
                    "short_flow_count": float(np.random.randint(0, 3)),
                    "pkts_per_sec": float(np.random.uniform(6.0, 25.0)),
                    "bytes_per_sec": float(np.random.uniform(1500.0, 9000.0)),
                    "concurrent_flows": float(np.random.randint(1, 4)),
                    "suricata_alert_count": float(np.random.choice([0, 1, 2], p=[0.4, 0.4, 0.2])),
                }
            elif label == "scan":
                row = {
                    "url_length": float(np.random.randint(18, 55)),
                    "special_char_count": float(np.random.randint(1, 5)),
                    "sql_keyword_count": 0.0,
                    "param_entropy": float(np.random.uniform(1.0, 3.2)),
                    "method_is_post": 0.0,
                    "status": float(np.random.choice([404, 403, 200], p=[0.8, 0.15, 0.05])),
                    "is_login_path": float(np.random.choice([0.0, 1.0], p=[0.8, 0.2])),
                    "user_agent_flag": float(np.random.choice([0.0, 1.0], p=[0.1, 0.9])),
                    "req_rate": float(np.random.uniform(10.0, 30.0)),
                    "unique_urls": float(np.random.randint(15, 45)),
                    "ratio_4xx": float(np.random.uniform(0.75, 0.98)),
                    "login_fail_count": float(np.random.choice([0, 1], p=[0.9, 0.1])),
                    "inter_request_time": float(np.random.uniform(0.04, 0.2)),
                    "unique_dst_ports": float(np.random.randint(2, 12)),
                    "short_flow_count": float(np.random.randint(5, 25)),
                    "pkts_per_sec": float(np.random.uniform(30.0, 120.0)),
                    "bytes_per_sec": float(np.random.uniform(5000.0, 30000.0)),
                    "concurrent_flows": float(np.random.randint(5, 18)),
                    "suricata_alert_count": float(np.random.randint(1, 6)),
                }
            elif label == "bruteforce":
                row = {
                    "url_length": float(np.random.randint(18, 35)),
                    "special_char_count": float(np.random.randint(1, 4)),
                    "sql_keyword_count": 0.0,
                    "param_entropy": float(np.random.uniform(2.2, 4.0)),
                    "method_is_post": 1.0,
                    "status": float(np.random.choice([401, 403, 200, 302], p=[0.6, 0.2, 0.1, 0.1])),
                    "is_login_path": 1.0,
                    "user_agent_flag": float(np.random.choice([0.0, 1.0], p=[0.3, 0.7])),
                    "req_rate": float(np.random.uniform(6.0, 18.0)),
                    "unique_urls": float(np.random.randint(1, 2)),
                    "ratio_4xx": float(np.random.uniform(0.5, 0.9)),
                    "login_fail_count": float(np.random.randint(4, 18)),
                    "inter_request_time": float(np.random.uniform(0.08, 0.3)),
                    "unique_dst_ports": 1.0,
                    "short_flow_count": float(np.random.randint(2, 8)),
                    "pkts_per_sec": float(np.random.uniform(15.0, 50.0)),
                    "bytes_per_sec": float(np.random.uniform(3000.0, 15000.0)),
                    "concurrent_flows": float(np.random.randint(2, 8)),
                    "suricata_alert_count": float(np.random.choice([0, 1, 2], p=[0.5, 0.3, 0.2])),
                }
            else:  # dos
                row = {
                    "url_length": float(np.random.randint(15, 40)),
                    "special_char_count": float(np.random.randint(0, 2)),
                    "sql_keyword_count": 0.0,
                    "param_entropy": float(np.random.uniform(0.8, 2.5)),
                    "method_is_post": float(np.random.choice([0.0, 1.0], p=[0.7, 0.3])),
                    "status": float(np.random.choice([503, 504, 200, 429], p=[0.5, 0.3, 0.1, 0.1])),
                    "is_login_path": 0.0,
                    "user_agent_flag": float(np.random.choice([0.0, 1.0], p=[0.5, 0.5])),
                    "req_rate": float(np.random.uniform(60.0, 300.0)),
                    "unique_urls": float(np.random.randint(1, 3)),
                    "ratio_4xx": float(np.random.uniform(0.1, 0.4)),
                    "login_fail_count": 0.0,
                    "inter_request_time": float(np.random.uniform(0.003, 0.02)),
                    "unique_dst_ports": 1.0,
                    "short_flow_count": float(np.random.randint(15, 55)),
                    "pkts_per_sec": float(np.random.uniform(200.0, 1500.0)),
                    "bytes_per_sec": float(np.random.uniform(60000.0, 600000.0)),
                    "concurrent_flows": float(np.random.randint(20, 90)),
                    "suricata_alert_count": float(np.random.randint(2, 8)),
                }

            row["label"] = label
            data_rows.append(row)

    df = pd.DataFrame(data_rows)
    # Xáo trộn ngẫu nhiên dữ liệu để mô phỏng lưu lượng thực tế và phân chia train/test chuẩn xác
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    # Lưu đúng thứ tự FEATURE_COLUMNS + label
    df = df[FEATURE_COLUMNS + ["label"]]
    df.to_csv(output_path, index=False)
    print(f"[+] Da tao tap du lieu CSV mau tai: {output_path} ({len(df)} dong)")


def generate_sample_eve_json(output_path: str = "data/sample_eve.json") -> None:
    """
    Sinh chuỗi sự kiện Suricata EVE JSON mô phỏng gồm:
    - Lưu lượng bình thường từ người dùng hợp lệ 192.168.1.50
    - Chuỗi tấn công SQLi tăng dần từ Kali 192.168.1.150
    - Chuỗi dò quét Scan từ 192.168.1.180
    - Chuỗi dò mật khẩu Bruteforce từ 192.168.1.190
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    base_time = datetime.now() - timedelta(minutes=5)
    events: list[dict] = []

    # 1. Lưu lượng bình thường
    for i in range(8):
        t = base_time + timedelta(seconds=i * 5)
        events.append({
            "timestamp": t.isoformat(),
            "event_type": "http",
            "src_ip": "192.168.1.50",
            "src_port": 50000 + i,
            "dest_ip": "192.168.1.10",
            "dest_port": 80,
            "http": {
                "http_method": "GET",
                "url": f"/index.php?page=view&item={i}",
                "status": 200,
                "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            },
        })

    # 2. Tấn công SQLi từ Kali (192.168.1.150) -> kích hoạt điểm S_t tăng dần và vượt theta
    sqli_payloads = [
        "/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit",
        "/dvwa/vulnerabilities/sqli/?id=1%27&Submit=Submit",
        "/dvwa/vulnerabilities/sqli/?id=1%27%20OR%201=1--&Submit=Submit",
        "/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20null,%20version()--&Submit=Submit",
        "/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20user,password%20FROM%20users--&Submit=Submit",
        "/dvwa/vulnerabilities/sqli/?id=1%27%20AND%20sleep(5)--&Submit=Submit",
    ]
    t_sqli = base_time + timedelta(seconds=30)
    for i, payload in enumerate(sqli_payloads):
        curr_t = t_sqli + timedelta(seconds=i * 2)
        events.append({
            "timestamp": curr_t.isoformat(),
            "event_type": "http",
            "src_ip": "192.168.1.150",
            "src_port": 45000 + i,
            "dest_ip": "192.168.1.10",
            "dest_port": 80,
            "http": {
                "http_method": "GET",
                "url": payload,
                "status": 200 if i < 4 else 500,
                "http_user_agent": "sqlmap/1.6#stable (https://sqlmap.org)",
            },
        })
        # Kèm sự kiện flow và alert của Suricata
        events.append({
            "timestamp": curr_t.isoformat(),
            "event_type": "flow",
            "src_ip": "192.168.1.150",
            "dest_port": 80,
            "flow": {
                "pkts_toserver": 12,
                "pkts_toclient": 14,
                "bytes_toserver": 1800,
                "bytes_toclient": 6500,
                "age": 0.5,
            },
        })
        if i >= 2:
            events.append({
                "timestamp": curr_t.isoformat(),
                "event_type": "alert",
                "src_ip": "192.168.1.150",
                "alert": {
                    "signature": "ET WEB_SPECIFIC_APPS DVWA SQL Injection Attempt",
                    "severity": 1,
                },
            })

    # 3. Quét đường dẫn Web Scan từ 192.168.1.180
    t_scan = base_time + timedelta(seconds=60)
    scan_paths = [
        "/admin.php", "/wp-login.php", "/phpmyadmin/", "/backup.zip",
        "/.env", "/config.json", "/api/v1/users", "/server-status"
    ]
    for i, p in enumerate(scan_paths):
        curr_t = t_scan + timedelta(milliseconds=i * 300)
        events.append({
            "timestamp": curr_t.isoformat(),
            "event_type": "http",
            "src_ip": "192.168.1.180",
            "src_port": 39000 + i,
            "dest_ip": "192.168.1.10",
            "dest_port": 80,
            "http": {
                "http_method": "GET",
                "url": p,
                "status": 404,
                "http_user_agent": "gobuster/3.1.0",
            },
        })
        events.append({
            "timestamp": curr_t.isoformat(),
            "event_type": "flow",
            "src_ip": "192.168.1.180",
            "dest_port": 80,
            "flow": {
                "pkts_toserver": 4,
                "pkts_toclient": 4,
                "bytes_toserver": 320,
                "bytes_toclient": 450,
                "age": 0.05,
            },
        })

    # 4. Tấn công Bruteforce từ 192.168.1.190
    t_bf = base_time + timedelta(seconds=90)
    for i in range(6):
        curr_t = t_bf + timedelta(milliseconds=i * 400)
        events.append({
            "timestamp": curr_t.isoformat(),
            "event_type": "http",
            "src_ip": "192.168.1.190",
            "src_port": 41000 + i,
            "dest_ip": "192.168.1.10",
            "dest_port": 80,
            "http": {
                "http_method": "POST",
                "url": "/dvwa/login.php",
                "status": 401,
                "http_user_agent": "hydra/9.3",
                "http_request_body": f"username=admin&password=pass{i}&Login=Login",
            },
        })

    # Sắp xếp các sự kiện theo đúng dòng thời gian timestamp
    events.sort(key=lambda e: e["timestamp"])

    with open(output_path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    print(f"[+] Da tao tap log Suricata EVE mau tai: {output_path} ({len(events)} su kien)")


if __name__ == "__main__":
    generate_dataset_csv("data/sample_dataset.csv", samples_per_class=500)
    generate_sample_eve_json("data/sample_eve.json")
