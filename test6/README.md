# HƯỚNG DẪN VẬN HÀNH CHI TIẾT HỆ THỐNG AI-IDS WEB SERVER (LAB VMWARE)
**AI Early Web Attack Detection System (pfSense + Suricata IDS + PostgreSQL + Ensemble RF & LSTM + SOC Dashboard)**

---

## 1. Tổng quan & Thông số Mạng Lab

Hệ thống được thiết kế để phát hiện sớm các hành vi tấn công máy chủ Web Server thông qua phân tích luồng log **Suricata EVE JSON** từ **pfSense**, kết hợp cơ sở dữ liệu trung tâm **PostgreSQL**, mô hình học máy **Random Forest** và mô hình chuỗi thời gian **LSTM Deep Learning**, hiển thị cảnh báo trực quan trên **SOC Dashboard**.

### Thông tin mạng thực tế:
- **pfSense Firewall & Router**:
  - Giao diện WAN: `192.168.159.136`
  - Giao diện LAN: `192.168.78.136`
  - Cổng quản trị SSH/SFTP: `22` (Tài khoản: `admin` / Mật khẩu: `123456`)
- **Ubuntu Server (Web Server, CSDL, IDS & Dashboard)**:
  - Địa chỉ IP: `192.168.159.135` (Giao diện `ens33`)
  - Web Server: Apache2 lắng nghe cổng `80` (chạy DVWA tại `http://127.0.0.1/dvwa/login.php`)
  - Cơ sở dữ liệu: PostgreSQL 16+ lắng nghe cổng `5432` (`ids_system` / `ids_user`)
  - Dashboard: Flask Web Application lắng nghe cổng `5000` (`http://0.0.0.0:5000`)
- **Kali Linux (Máy tấn công thử nghiệm trong lab)**:
  - Khuyến nghị đặt card mạng ở dải pfSense LAN (`192.168.78.x`) trỏ gateway về `192.168.78.136` để lưu lượng HTTP đến Ubuntu Web Server (`192.168.159.135:80`) bắt buộc phải đi qua pfSense và được Suricata kiểm tra.

### 1.1 Luồng dữ liệu chuẩn (PostgreSQL là trung tâm)

Ứng dụng trong `test6/` chạy theo đúng một đường ống, không đọc file log trực tiếp trên Dashboard:

```
pfSense / Suricata
      │  eve.json (SSH/SFTP → data/pfsense_eve.json)
      ▼
┌─────────────────────┐
│ Collector           │  src/pfsense_collector.py + src/collector.py
│ (tail file, parse)  │  ghi từng sự kiện vào raw_events (event_hash UNIQUE)
└─────────┬───────────┘
          │ INSERT raw_events (processing_status = 'pending')
          ▼
┌─────────────────────┐
│ PostgreSQL          │  ids_system
│ raw_events          │  hàng đợi sự thật duy nhất (queue + lease + retry)
└─────────┬───────────┘
          │ claim_pending()  FOR UPDATE SKIP LOCKED
          ▼
┌─────────────────────┐
│ AI Worker           │  src/main.py::_process_events_worker
│ features + model    │  ghi network_features và ai_predictions
│ alert manager       │  ghi alerts (kèm evidence JSONB)
└─────────┬───────────┘
          │ alerts / ai_predictions
          ▼
┌─────────────────────┐
│ Flask Dashboard     │  src/dashboard.py  (http://localhost:5000)
│ chỉ đọc PostgreSQL  │  /api/status, /api/alerts, /api/alerts/<id>/detail
└─────────────────────┘
```

Nguyên tắc bắt buộc:

- **Collector không gọi model.** Nó chỉ chuẩn hóa EVE JSON và ghi `raw_events`.
- **Worker không đọc file log.** Nó chỉ `claim` các bản ghi `pending` trong `raw_events`.
- **Dashboard không đọc file log hay file model.** Mọi số liệu lấy từ 4 bảng PostgreSQL.
- Mỗi sự kiện chỉ được xử lý một lần nhờ `raw_events.event_hash` (UNIQUE) và cơ chế lease `processing_status` / `lease_until`.
- Sự kiện lỗi được trả lại hàng đợi với `next_retry_at` (backoff), sau 3 lần thất bại chuyển `failed` để không chặn queue.

---

## 2. Chuẩn bị Môi trường trên Ubuntu

### Bước 2.1: Kích hoạt môi trường ảo Python
Môi trường Python ảo đã được cấu hình sẵn tại `venv/`:
```bash
cd /home/nhom4/test6
source venv/bin/activate
```
*Kiểm tra phiên bản:*
```bash
python --version   # Python 3.14.4
pip list           # Đã cài đặt Flask, scikit-learn, psycopg2-binary, pandas, numpy, paramiko...
```

### Bước 2.2: Kiểm tra dịch vụ PostgreSQL
Đảm bảo PostgreSQL đang chạy và cơ sở dữ liệu `ids_system` sẵn sàng:
```bash
# Kiểm tra dịch vụ
systemctl status postgresql --no-pager

# Kiểm tra kết nối tới database ids_system
PGPASSWORD=123456 psql -h 127.0.0.1 -U ids_user -d ids_system -c "\dt"
```
*(Nếu cần tạo mới CSDL và người dùng:)*
```bash
sudo -u postgres psql -c "CREATE USER ids_user WITH PASSWORD '123456';"
sudo -u postgres psql -c "CREATE DATABASE ids_system OWNER ids_user;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ids_system TO ids_user;"
```

### Bước 2.3: Kiểm tra máy chủ Web Apache2 & DVWA
```bash
# Kiểm tra dịch vụ Apache2
sudo systemctl status apache2 --no-pager

# Kiểm tra ứng dụng DVWA
curl -I http://127.0.0.1/dvwa/login.php
```

---

## 3. Cấu hình pfSense và Suricata gửi Log sang Ubuntu

Để Ubuntu thu thập được luồng log EVE JSON từ pfSense, thực hiện theo các bước:

### Bước 3.1: Kích hoạt EVE JSON Log trên pfSense
1. Mở trình duyệt truy cập WebGUI pfSense: `https://192.168.159.136` (hoặc `https://192.168.78.136`).
2. Vào menu **Services > Suricata > Interfaces**.
3. Chọn giao diện đang giám sát (ví dụ `WAN` - `em0` hoặc `LAN` - `em1`). Bấm icon cây bút để chỉnh sửa.
4. Cuộn xuống phần **Logging Settings**:
   - Tích chọn: **Enable EVE JSON Log output**.
   - Tích chọn các sự kiện quan sát cần thiết:
     - [x] **Alerts**
     - [x] **HTTP** (bắt buộc để giám sát Web Server)
     - [x] **Track Flow Summary**
     - [x] **DNS**
     - [x] **TLS**
   - Log Output type: Chọn **EVE JSON File** (Suricata sẽ ghi ra `/var/log/suricata/*/eve.json`).
5. Bấm **Save** và nhấn biểu tượng Restart Suricata trên giao diện đó.

### Bước 3.2: Bật dịch vụ SSH trên pfSense
1. Vào menu **System > Advanced > Admin Access**.
2. Tích chọn **Enable Secure Shell**.
3. Cổng SSH: `22`.
4. Bấm **Save**.

### Bước 3.3: Kiểm tra đường truyền SSH/SFTP từ Ubuntu
Tại terminal Ubuntu, chạy lệnh kiểm tra kết nối và đường dẫn log:
```bash
ssh admin@192.168.159.136 "ls -lh /var/log/suricata/*/eve.json"
```
*(Hệ thống thu thập log trong mã nguồn sẽ tự động kết nối và đọc chính xác các byte mới được ghi mà không cần kéo lại toàn bộ file).*

---

## 4. Huấn luyện Mô hình AI (Random Forest & LSTM)

Hệ thống hỗ trợ 2 mô hình học máy phân tích đa lớp:
- **Random Forest**: Phân loại đặc trưng lưu lượng tĩnh, tốc độ request, URL entropy, từ khóa SQL Injection.
- **Deep Learning LSTM**: Phân loại chuỗi thời gian (time-series sequence, `seq_len = 5`) xây dựng bằng **Pure NumPy** (Zero-Dependency), tương thích 100% với Python 3.14 và không tốn dung lượng ổ đĩa.

### Bước 4.1: Sinh tập dữ liệu mẫu và log EVE mẫu (nếu cần demo)
```bash
python3 src/generate_sample_data.py
```
*Tập dữ liệu sẽ được tạo tại `data/sample_dataset.csv` và `data/sample_eve.json`.*

### Bước 4.2: Huấn luyện mô hình
```bash
python3 src/train.py
```
*Kết quả huấn luyện:*
- Random Forest: `models/detector_model.joblib`
- LSTM Detector: `models/lstm_model.joblib`
- Hiển thị bảng chỉ số đánh giá: **Accuracy, Precision, Recall, Macro-F1, False Positive Rate (FPR)** và ma trận nhầm lẫn.

---

## 5. Các Cách Khởi Chạy Ứng Dụng

> **Thứ tự vận hành:** PostgreSQL → Collector + AI Worker → Dashboard.
> `python3 src/main.py` chạy đồng thời cả ba chặng (collector, worker AI, Flask),
> `python3 run_flask.py` chỉ chạy Dashboard và **không** thu thập/phân tích log.

### Cách 1: Chạy toàn bộ pipeline (Khuyến nghị)
Khởi chạy đồng thời bộ thu thập log Suricata (`PfSenseCollector` + `LogCollector`),
Worker AI (feature extraction, Random Forest/LSTM, alert manager) và Dashboard:
```bash
cd /home/nhom4/test6
source venv/bin/activate
python3 src/main.py
```
Mở trình duyệt (từ máy Ubuntu hoặc máy trong cùng mạng lab):
```
http://localhost:5000
hoặc
http://192.168.159.135:5000
```
*Sự kiện mới chỉ được thu thập/phân tích khi tiến trình này đang chạy, vì đây là nơi
duy nhất đọc `eve.json`, ghi `raw_events`, chạy model và tạo `alerts`.*

### Cách 2: Chạy riêng Web Dashboard Flask (chế độ chỉ đọc)
Dùng khi pipeline (collector + worker) đã chạy ở terminal/service khác, hoặc khi chỉ
cần xem lại dữ liệu đã có trong PostgreSQL:
```bash
python3 run_flask.py
```
Script này khởi tạo `PostgresStore`, đảm bảo schema tồn tại và đọc 4 bảng
`raw_events` / `network_features` / `ai_predictions` / `alerts`.
Nó **không** thu thập log mới và **không** chạy model.

### Cách 3: Chạy Native Desktop GUI (Desktop Window)
Nếu làm việc trực tiếp trên màn hình đồ họa Ubuntu Desktop (GNOME):
```bash
python3 desktop_app.py
```
*(Cửa sổ Desktop độc lập sẽ mở ra với các biểu đồ Chart.js tự động cập nhật.)*

### Cách 4: Chạy nền bằng systemd
Mẫu unit `ai-ids.service` đã có sẵn trong thư mục dự án và trỏ tới
`/home/nhom4/test6` (user `nhom4`). Nếu triển khai ở đường dẫn/user khác, sửa
`WorkingDirectory`, `ExecStart`, `User` và `Group` trước khi cài:
```bash
sudo cp ai-ids.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ai-ids
sudo journalctl -u ai-ids -f
```

### Kiểm tra pipeline đang chạy đúng
```bash
# 1. Các chặng có tiến triển không (pending giảm, processed/predictions tăng)
PGPASSWORD=123456 psql -h 127.0.0.1 -U ids_user -d ids_system -c "
SELECT processing_status, count(*) FROM raw_events GROUP BY 1 ORDER BY 1;"

# 2. Worker đã tạo dự đoán chưa
PGPASSWORD=123456 psql -h 127.0.0.1 -U ids_user -d ids_system -c "
SELECT model_name, predicted_label, count(*) FROM ai_predictions GROUP BY 1,2 ORDER BY 3 DESC LIMIT 10;"

# 3. Cảnh báo mới nhất kèm nguồn phát hiện
PGPASSWORD=123456 psql -h 127.0.0.1 -U ids_user -d ids_system -c "
SELECT id, ts, src_ip, attack_type, severity, status, source_of_detection
FROM alerts ORDER BY id DESC LIMIT 10;"

# 4. Dashboard đọc đúng PostgreSQL
curl -s http://127.0.0.1:5000/api/status | python3 -m json.tool
```
Nếu `raw_events` có `pending` tăng nhưng `processed`/`ai_predictions` không tăng,
Worker AI chưa chạy hoặc đang lỗi — xem mục 8 (Troubleshooting).

---

## 6. Các Chức Năng Trên Giao Diện SOC Dashboard

1. **Bảng Thống Kê Tổng Quan (đọc từ PostgreSQL)**:
   - `raw_events`: tổng số sự kiện, số `pending`, `processing`, `processed`, `failed`.
   - `ai_predictions`: số lượt suy luận theo model (Random Forest, LSTM, Suricata signature).
   - `alerts`: cảnh báo chữ ký Suricata, cảnh báo AI và số sự cố chưa xử lý.
   - Trạng thái từng chặng (collector / worker / db) và độ trễ xử lý gần nhất.
2. **Biểu Đồ Thời Gian Thực (Chart.js)**:
   - *Line Chart*: Điểm bất thường tích lũy $S_t$ (EMA Anomaly Score) nhảy theo thời gian với các ngưỡng cảnh báo $\theta$.
   - *Doughnut Chart*: Phân bố tỷ lệ các loại tấn công (`normal`, `scan`, `sqli`, `bruteforce`, `dos`).
   - *Bar Chart*: Phân loại trạng thái sự cố và phân bố sự kiện EVE.
3. **Bảng Cảnh Báo Trực Tiếp**:
   - Hiển thị IP nguồn, IP đích, Loại hành vi, Mức độ rủi ro (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), Nguồn phát hiện (Suricata / AI RF / AI LSTM / Hybrid Ensemble).
   - Nút **Chi tiết** gọi `/api/alerts/<id>/detail` để dựng hồ sơ bằng chứng: sự kiện EVE gốc trong `raw_events`, vector đặc trưng trong `network_features`, xác suất từng lớp trong `ai_predictions`, URL/User-Agent/tham số và `event_id` để truy vết.
4. **Phòng Thủ Thủ Công (Manual Defense)**:
   - Chuyên viên bấm đổi trạng thái sự cố: `Mới` &rarr; `Đang xác minh` &rarr; `Đã xác nhận` &rarr; `Đã xử lý` &rarr; `Cảnh báo nhầm`.
   - Nhập ghi chú xử lý lưu trực tiếp vào PostgreSQL.
   - Gợi ý lệnh chặn/gỡ chặn tường lửa để chuyên viên thực thi thủ công (hệ thống **không tự ý can thiệp** firewall).

---

## 7. Kiểm Thử Pipeline Bằng Kịch Bản Tấn Công Lab

Để xác minh hệ thống hoạt động chính xác từ khâu nhận log &rarr; AI phân tích &rarr; Dashboard hiển thị cảnh báo:

### Bài test 1: Tấn công Web SQL Injection (vào DVWA)
Từ máy Kali Linux hoặc dùng `curl`:
```bash
curl -s -i "http://192.168.159.135/dvwa/vulnerabilities/sqli/?id=1'%20UNION%20SELECT%20null,concat(user,0x3a,password)%20FROM%20users--&Submit=Submit" \
     -H "User-Agent: sqlmap/1.7#stable"
```
*Kết quả:* Dashboard hiển thị ngay lập tức cảnh báo `CRITICAL` / `HIGH` loại `SQLI`.

### Bài test 2: Quét cổng dịch vụ (Port Scan)
Từ máy Kali:
```bash
nmap -sS -p 21,22,80,443,3306,5432,8080 192.168.159.135
```
*Kết quả:* Hệ thống kích hoạt luật Flow và AI nhận diện `SCAN` với số lượng unique ports tăng cao.

### Bài test 3: Dò quét mật khẩu đăng nhập (Brute Force)
Từ máy Kali:
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.159.135 http-post-form "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:F=login failed"
```
*Kết quả:* Cảnh báo `BRUTEFORCE` xuất hiện dựa trên chuỗi request đăng nhập dồn dập và mã phản hồi 302/401/403.

### Bài test 4: Bắn lưu lượng kiểm thử qua script mẫu (Không gây tải mạng)
Nếu không bật Kali hoặc pfSense, có thể ghi trực tiếp một sự kiện EVE mẫu vào file
mà Collector đang tail. Khi `python3 src/main.py` đang chạy, Collector sẽ đọc dòng mới,
ghi vào `raw_events`, Worker AI xử lý và Dashboard hiển thị cảnh báo:
```bash
cd /home/nhom4/test6
python3 - <<'PY'
import json, datetime
event = {
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "event_type": "http",
    "src_ip": "192.168.159.201",
    "src_port": 52140,
    "dest_ip": "192.168.159.135",
    "dest_port": 80,
    "proto": "TCP",
    "http": {
        "hostname": "192.168.159.135",
        "url": "/dvwa/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20null,password%20FROM%20users--",
        "http_method": "GET",
        "status": 500,
        "http_user_agent": "sqlmap/1.7#stable",
    },
}
with open("data/pfsense_eve.json", "a", encoding="utf-8") as f:
    f.write(json.dumps(event) + "\n")
print("Đã ghi sự kiện EVE mẫu")
PY
```
*Kiểm tra:* `curl -s http://127.0.0.1:5000/api/status` phải thấy `raw_total` tăng,
sau đó `raw_pending` giảm và `predictions_total`/`alerts_total` tăng.

Ngoài ra có thể dùng script mẫu của dự án tham chiếu (ghi trực tiếp vào `raw_events`
của cùng CSDL `ids_system`):
```bash
python3 /home/nhom4/ai_ids/scripts/test_log_sender.py --attack all
```

---

## 8. Hướng Dẫn Xử Lý Sự Cố Thường Gặp (Troubleshooting)

| Hiện tượng | Nguyên nhân | Cách khắc phục |
| :--- | :--- | :--- |
| **pfSense SSH Connect Failed** | Máy ảo pfSense chưa bật hoặc IP khác | Kiểm tra `ping 192.168.159.136`. Vào pfSense WebGUI bật **Enable Secure Shell** (cổng 22). |
| **Không thấy cảnh báo khi Kali tấn công** | Kali và Ubuntu cùng dải `192.168.159.x`, lưu lượng đi thẳng L2 không qua pfSense | Chuyển card mạng Kali sang dải LAN pfSense (`192.168.78.x`), đặt gateway trỏ về `192.168.78.136`. |
| **Cảnh báo cũ cứ hiện lại khi mở Dashboard** | Cảnh báo lưu vĩnh viễn trong CSDL PostgreSQL | Trong file `config.yaml`, đặt `alert.show_only_current_session: true` hoặc bấm nút **"Xóa cảnh báo cũ"** trên Dashboard. |
| **`raw_events` tăng nhưng không có `ai_predictions`** | Worker AI chưa chạy (chỉ chạy `run_flask.py`), hoặc `database.enabled=false` | Chạy `python3 src/main.py`; kiểm tra log `EventWorkerThread`; xác nhận `config.yaml` có `database.enabled: true`. |
| **`raw_events` đầy bản ghi `pending`/`processing`** | Worker dừng đột ngột, lease còn giữ, hoặc sự kiện lỗi | Xem cột `last_error`, `processing_attempts`; worker tự retry tối đa 3 lần. Sự kiện `failed` không chặn queue. Có thể reset thủ công: `UPDATE raw_events SET processing_status='pending', lease_until=NULL WHERE processing_status='processing' AND lease_until < now();` |
| **Dashboard trống dù log mới vẫn về** | Dashboard đang lọc theo phiên (`show_only_current_session: true`) và cảnh báo cũ không thuộc phiên hiện tại | Tắt lọc trong `config.yaml` hoặc xem trực tiếp bảng `alerts`; kiểm tra `/api/status` xem `raw_events`/`ai_predictions` có tăng. |
| **Giao diện hiện khung nhưng số liệu đều 0, nút bấm không phản hồi** | Inline JavaScript bị lỗi cú pháp (thường do chuỗi `\n` không escape) hoặc trình duyệt còn cache bản cũ | Nhấn `Ctrl + F5` để tải lại; kiểm tra Console (F12). Chạy `venv/bin/python -m pytest tests/test_dashboard_js.py -q` để kiểm tra cú pháp JS; khởi động lại `python3 src/main.py` sau khi sửa `src/dashboard.py`. |
| **Sự kiện bị bỏ qua với lý do "quá cũ"** | `detection.max_event_age_seconds` giới hạn tuổi sự kiện | Đặt `max_event_age_seconds: 0` để phân tích cả backlog (dedup `event_hash` vẫn chống phát lại). |
| **Log bị xử lý trùng sau khi đọc lại file** | Collector đọc lại từ đầu file | Giữ `log.start_at_end: true` và `pfsense.start_from_end: true`; `event_hash` UNIQUE trong `raw_events` tự chặn bản ghi trùng. |
| **Lỗi kết nối PostgreSQL (Connection refused)** | Dịch vụ postgresql bị dừng | Chạy `sudo systemctl restart postgresql`. Kiểm tra cổng 5432 bằng `ss -tlnp \| grep 5432`. |
| **Tràn dung lượng ổ đĩa (Disk Quota Exceeded)** | Phân vùng root `/` chỉ còn ~1.7GB trống | Tuyệt đối không cài các gói nặng như CUDA, PyTorch (>1.5GB). Sử dụng phiên bản Pure NumPy LSTM có sẵn trong mã nguồn. |

---

## 9. Cấu Trúc Các Tệp Mã Nguồn Chính Trong `test6/`

```
/home/nhom4/test6/
├── config.yaml              # File cấu hình trung tâm (Database, pfSense, Detection thresholds)
├── requirements.txt         # Danh sách thư viện Python cần thiết
├── run_flask.py             # Script chạy riêng Flask Dashboard (Port 5000)
├── desktop_app.py           # Ứng dụng Desktop GUI
├── src/
│   ├── main.py              # Pipeline: Collector + AI Worker + Flask Dashboard
│   ├── dashboard.py         # Mã nguồn Flask Dashboard & REST APIs (chỉ đọc PostgreSQL)
│   ├── pg_store.py          # Data layer PostgreSQL: schema, queue/lease, predictions, alerts, forensic
│   ├── pfsense_collector.py # Bộ thu thập log Suricata từ pfSense qua SFTP
│   ├── collector.py         # Tail file EVE JSON → raw_events
│   ├── db.py                # CRUD cảnh báo, blocked IP, whitelist, migrate schema
│   ├── features.py          # Trích xuất 17 đặc trưng mạng & web indicators
│   ├── model.py             # Lớp bao gói mô hình Ensemble
│   ├── lstm_numpy.py        # Mô hình Deep Learning LSTM thuần bằng NumPy
│   ├── train.py             # Huấn luyện Random Forest và LSTM
│   ├── alert_manager.py     # Quản lý cảnh báo, cooldown, manual defense
│   └── scorer.py            # Tính điểm bất thường lũy tích S_t
├── models/
│   ├── detector_model.joblib # Trọng số mô hình Random Forest đã huấn luyện
│   └── lstm_model.joblib     # Trọng số mô hình LSTM đã huấn luyện
├── data/
│   ├── sample_dataset.csv   # Dữ liệu huấn luyện mẫu (2500 dòng, 5 lớp)
│   ├── sample_eve.json      # File log Suricata EVE mẫu
│   └── pfsense_eve.json     # File log EVE đồng bộ thực tế từ pfSense
└── tests/                   # Bộ kiểm thử tự động
```

---

## 10. Schema PostgreSQL & Khóa Cấu Hình Pipeline

### 10.1 Bốn bảng trung tâm trong `ids_system`

| Bảng | Vai trò | Cột chính |
| :--- | :--- | :--- |
| `raw_events` | Hàng đợi sự thật duy nhất; Collector ghi, Worker đọc | `id`, `event_timestamp`, `event_type`, `src_ip`, `dest_ip`, `dest_port`, `raw_json` (JSONB), `event_hash` (UNIQUE), `processed`, `processing_status` (`pending`/`processing`/`processed`/`failed`), `processing_attempts`, `lease_until`, `next_retry_at`, `last_error` |
| `network_features` | Vector đặc trưng theo cửa sổ thời gian do Worker trích xuất | `event_id` → `raw_events.id`, `src_ip`, `http_request_count`, `http_error_ratio`, `failed_login_count`, `unique_destination_ports`, `param_entropy`, `sql_keyword_count`, `user_agent_flag`, `feature_schema_version` |
| `ai_predictions` | Kết quả suy luận của từng model | `event_id`, `model_name`, `model_version`, `predicted_label`, `confidence`, `risk_level`, `inference_latency_ms`, `explanation` (JSONB) |
| `alerts` | Cảnh báo đã gom nhóm, Dashboard đọc trực tiếp | `id`, `ts`, `src_ip`, `dest_ip`, `attack_type`, `score`, `severity`, `status`, `source_of_detection`, `confidence`, `evidence` (JSONB, chứa `event_id`, URL, User-Agent, xác suất lớp), `alert_timestamp` |

Ghi chú vận hành:

- Schema được tạo/cập nhật tự động bằng `CREATE TABLE IF NOT EXISTS` và
  `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, an toàn với CSDL đã có dữ liệu.
- `raw_events.event_hash` là SHA-256 của JSON đã chuẩn hóa (bỏ các trường thời gian
  dễ thay đổi), nhờ đó Collector có thể chạy lại mà không nhân đôi sự kiện.
- Worker claim theo lô bằng `FOR UPDATE SKIP LOCKED`, nên có thể chạy nhiều worker
  song song mà không xử lý trùng.
- `ai_predictions` chống trùng theo bộ `(event_id, model_name, model_version)`.

### 10.2 Khóa cấu hình quan trọng trong `config.yaml`

```yaml
database:
  enabled: true            # BẮT BUỘC true để pipeline chạy qua PostgreSQL
  host: 127.0.0.1
  port: 5432
  dbname: ids_system
  user: ids_user
  password: '123456'
  connect_timeout: 5

worker:
  batch_size: 20           # Số sự kiện claim mỗi vòng
  poll_interval: 0.2       # Giây chờ khi queue rỗng

log:
  path: data/pfsense_eve.json
  start_at_end: true       # Chỉ đọc phần mới ghi thêm
  poll_interval: 0.2

pfsense:
  enabled: true
  host: 192.168.78.136
  method: ssh_sftp
  suricata_log_path: /var/log/suricata/eve.json
  local_log_path: data/pfsense_eve.json
  start_from_end: true

detection:
  max_event_age_seconds: 0 # 0 = phân tích cả backlog; >0 = bỏ qua sự kiện quá cũ

alert:
  auto_block_enabled: false
  cooldown_seconds: 30
  show_only_current_session: true

dashboard:
  host: 0.0.0.0
  port: 5000
```

### 10.3 API Dashboard liên quan pipeline

| Endpoint | Mô tả |
| :--- | :--- |
| `GET /api/status` | Thống kê `raw_events` theo trạng thái, số `ai_predictions`, số `alerts`, trạng thái collector/worker/DB |
| `GET /api/alerts` | Danh sách cảnh báo mới nhất từ bảng `alerts` |
| `GET /api/alerts/<id>/detail` | Hồ sơ bằng chứng: `raw_events` gốc + `network_features` + toàn bộ `ai_predictions` của `event_id` |
| `POST /api/alerts/<id>/block` | Chặn IP thủ công (khi bật `auto_block_enabled`) |
| `POST /api/alerts/<id>/ignore` | Đánh dấu cảnh báo nhầm |
| `GET /api/stats` | Số liệu biểu đồ phân bố tấn công/trạng thái |
