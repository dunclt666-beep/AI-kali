# AI Early Web Attack Detection System (Suricata IDS & Ensemble RF + LSTM)

Hệ thống AI phát hiện sớm tấn công web server tích hợp Suricata IDS, sử dụng mô hình kết hợp **Ensemble (Random Forest + LSTM Time-Series Deep Learning)** và giao diện Desktop SOC Dashboard trực quan với các biểu đồ thời gian thực.

---

### 1. Cài đặt môi trường và thư viện
```bash
# Kích hoạt môi trường ảo (nếu có)
source venv/bin/activate

# Cài đặt các thư viện Python
pip install -r requirements.txt
```

#### Cấu hình PostgreSQL

Ứng dụng dùng PostgreSQL cho cảnh báo, IP bị chặn, whitelist và metadata mô hình.
Hãy cài PostgreSQL, tạo role/database, rồi cập nhật các trường trong `database`
của `config.yaml`:

```sql
CREATE USER ids_user WITH PASSWORD 'use-a-strong-password';
CREATE DATABASE ids_system OWNER ids_user;
```

Không lưu mật khẩu thực trong YAML. Đặt biến môi trường trước khi chạy ứng dụng
(PowerShell):

```powershell
$env:POSTGRES_PASSWORD = "mật-khẩu-của-role"
```

Hoặc dùng `DATABASE_URL` thay các trường host/port/dbname/user/password. Ứng dụng
sẽ tự tạo schema khi khởi động. Ứng dụng **chỉ dùng PostgreSQL**: nếu không kết
nối được, chương trình báo lỗi rõ ràng thay vì âm thầm chuyển sang CSDL khác.

---

### 2. Sinh tập dữ liệu mẫu & log Suricata EVE
```bash
python3 src/generate_sample_data.py
```

---

### 3. Huấn luyện mô hình Ensemble (Random Forest + LSTM)
```bash
python3 src/train.py
```
*Script sẽ tự động huấn luyện:*
- **Random Forest**: Phân loại mức request và thống kê cửa sổ trượt.
- **LSTM (Keras/TensorFlow)**: Phân loại chuỗi hành vi thời gian (`seq_len = 5`).
- Đánh giá Precision, Recall, F1-Score, FPR của từng mô hình và mô hình Ensemble.
- Lưu tại `models/detector_model.joblib` và `models/lstm_model.keras`.

---

### 4. Khởi chạy Ứng dụng Desktop (Desktop Application)

#### Cách 1: Chạy trực tiếp dưới dạng Native Desktop App (Khuyên dùng)
```bash
python3 desktop_app.py
```
*(Cửa sổ ứng dụng Desktop riêng biệt sẽ mở ra ngay lập tức với đầy đủ 4 biểu đồ Chart.js trực quan).*

#### Cách 2: Chạy qua Electron Desktop App
```bash
cd electron
npm install
npm start
```

#### Cách 3: Chạy chế độ Web Server truyền thống
```bash
python3 src/main.py
```
Mở trình duyệt tại: `http://localhost:5000`

---

### 5. Các tính năng trên Giao diện Đồ họa

1. **Biểu đồ đường thời gian thực (Line Chart)**: Điểm bất thường tích lũy $S_t$ (EMA Anomaly Score) nhảy theo từng sự kiện, có vạch cảnh báo màu vàng tại ngưỡng $\theta = 0.7$ và vạch đỏ tại $0.9$.
2. **Biểu đồ tròn (Doughnut Chart)**: Phân bố tỷ lệ 5 loại lưu lượng (`normal`, `scan`, `sqli`, `bruteforce`, `dos`).
3. **Biểu đồ cột (Bar Chart)**: Thống kê số lượng IP đã tự động chặn (`auto_blocked`), chặn thủ công, và bỏ qua.
4. **Biểu đồ xu hướng (Timeline)**: Tần suất cảnh báo theo các khung giờ.
5. **Bảng cảnh báo trực tiếp**: Nút "Chặn" / "Bỏ qua", đồng hồ đếm ngược $5$ giây tự động thực thi.
6. **Quản lý Tường lửa & Whitelist**: Gỡ chặn IP, thêm IP tin cậy không bao giờ bị chặn.

---

### 6. Chống báo nhầm (false positive) & nhận diện đúng IP tấn công

Nếu hệ thống báo SCAN/DOS liên tục dù không có tấn công, hoặc cột IP hiển thị chính
máy web server, hãy kiểm tra các cấu hình sau trong `config.yaml`:

```yaml
network:
  # IP của web server: KHÔNG BAO GIỜ bị hiển thị là kẻ tấn công
  server_ips: ["192.168.78.132"]
  # Tự bảo vệ IP của máy đang chạy IDS (SSH/DNS/apt/dashboard không bị báo nhầm)
  protect_local_ips: true

log:
  # Không phát lại log cũ khi khởi động (tránh "bão cảnh báo" từ dữ liệu cũ)
  start_at_end: true

detection:
  scan_unique_ports: 12      # số cổng đích khác nhau mới coi là quét cổng
  dos_pps: 400               # gói/giây của MỘT luồng mới coi là flood
  http_bruteforce_login_fails: 5
  http_dos_req_rate: 25
  suricata_min_severity: 3   # bỏ qua chữ ký Suricata mức thấp/nhiễu
```

Nguyên tắc hoạt động:

- **IP tấn công** được suy ra theo chiều client/server của luồng (cổng dịch vụ), sau đó
  theo `server_ips` / `protected_networks`. Lưu lượng do chính server khởi tạo bị bỏ qua,
  không gán cho IP khác.
- **Chỉ cảnh báo khi có bằng chứng rõ ràng**: rất nhiều cổng đích khác nhau (quét cổng),
  tốc độ gói/giây rất cao (flood), payload SQL thật (kèm dấu `'`, `--`, `UNION ...`),
  User-Agent công cụ tấn công, nhiều lần đăng nhập thất bại...
- Các URL hợp lệ chứa từ khóa như `/delete.php`, `/update_profile.php`, health-check
  `curl` không còn bị coi là tấn công.
- Cảnh báo cũ trong CSDL có thể xoá bằng nút **"Xóa cảnh báo cũ"** ở tab Cảnh báo sớm.

Nếu vẫn còn báo nhầm, tăng `scan_unique_ports` / `dos_pps` hoặc xem log ứng dụng
(các dòng `Luật Flow phát hiện...`, `Luật HTTP fast-track phát hiện...` cho biết
luật nào kích hoạt và chỉ số tương ứng).
