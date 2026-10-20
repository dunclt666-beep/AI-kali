"""Generate figures for report sections 3.4 and 3.5 using Pillow."""
from __future__ import annotations

import math
import os
from PIL import Image, ImageDraw, ImageFont

BASE = os.path.dirname(os.path.abspath(__file__))
IMG = os.path.join(BASE, "images")
os.makedirs(IMG, exist_ok=True)

FONT_REG = "C:/Windows/Fonts/segoeui.ttf"
FONT_BOLD = "C:/Windows/Fonts/segoeuib.ttf"
FONT_ITALIC = "C:/Windows/Fonts/segoeuii.ttf"


def font(size: int, bold: bool = False, italic: bool = False):
    path = FONT_BOLD if bold else (FONT_ITALIC if italic else FONT_REG)
    return ImageFont.truetype(path, size)


def text_size(draw: ImageDraw.ImageDraw, text: str, fnt) -> tuple[int, int]:
    box = draw.textbbox((0, 0), text, font=fnt)
    return box[2] - box[0], box[3] - box[1]


def wrap_text(draw, text: str, fnt, max_width: int) -> list[str]:
    lines: list[str] = []
    for paragraph in text.split("\n"):
        current = ""
        for word in paragraph.split():
            test = (current + " " + word).strip()
            if text_size(draw, test, fnt)[0] <= max_width or not current:
                current = test
            else:
                lines.append(current)
                current = word
        if current:
            lines.append(current)
    return lines


def draw_center_text(draw, box, lines, fnt, fill="#0f172a", line_gap=6):
    x1, y1, x2, y2 = box
    rendered = []
    for line in lines:
        w, h = text_size(draw, line, fnt)
        rendered.append((line, w, h))
    total_h = sum(h for _, _, h in rendered) + line_gap * (len(rendered) - 1)
    y = y1 + (y2 - y1 - total_h) / 2
    for line, w, h in rendered:
        draw.text((x1 + (x2 - x1 - w) / 2, y), line, font=fnt, fill=fill)
        y += h + line_gap


def box(draw, xy, title, subtitle=None, fill="#e0f2fe", outline="#0284c7", radius=14,
        title_size=28, sub_size=21, title_color="#0c4a6e", sub_color="#334155",
        dashed=False, width=3):
    x1, y1, x2, y2 = xy
    if dashed:
        # Pillow rounded_rectangle has no dash support; draw dashed straight rectangle.
        dash = 14
        for x in range(x1, x2, dash * 2):
            draw.line([(x, y1), (min(x + dash, x2), y1)], fill=outline, width=width)
            draw.line([(x, y2), (min(x + dash, x2), y2)], fill=outline, width=width)
        for y in range(y1, y2, dash * 2):
            draw.line([(x1, y), (x1, min(y + dash, y2))], fill=outline, width=width)
            draw.line([(x2, y), (x2, min(y + dash, y2))], fill=outline, width=width)
    else:
        draw.rounded_rectangle(xy, radius=radius, fill=fill, outline=outline, width=width)
    fnt_t = font(title_size, bold=True)
    tw, th = text_size(draw, title, fnt_t)
    ty = y1 + 18
    draw.text((x1 + (x2 - x1 - tw) / 2, ty), title, font=fnt_t, fill=title_color)
    if subtitle:
        fnt_s = font(sub_size)
        lines = wrap_text(draw, subtitle, fnt_s, int((x2 - x1) - 34))
        draw_center_text(draw, (x1 + 16, ty + th + 12, x2 - 16, y2 - 12), lines, fnt_s,
                         fill=sub_color, line_gap=5)


def arrow(draw, start, end, color="#475569", width=4, label=None, label_font=None,
          label_offset=(0, 0), dashed=False):
    x1, y1 = start
    x2, y2 = end
    if dashed:
        dash = 12
        dx, dy = x2 - x1, y2 - y1
        dist = math.hypot(dx, dy)
        steps = max(1, int(dist // (dash * 2)))
        for i in range(steps + 1):
            t1 = min(1.0, (i * 2 * dash) / dist)
            t2 = min(1.0, (i * 2 * dash + dash) / dist)
            draw.line([(x1 + dx * t1, y1 + dy * t1), (x1 + dx * t2, y1 + dy * t2)],
                      fill=color, width=width)
    else:
        draw.line([start, end], fill=color, width=width)
    # Arrow head
    angle = math.atan2(y2 - y1, x2 - x1)
    size = 15
    p1 = (x2 - size * math.cos(angle - math.pi / 7), y2 - size * math.sin(angle - math.pi / 7))
    p2 = (x2 - size * math.cos(angle + math.pi / 7), y2 - size * math.sin(angle + math.pi / 7))
    draw.polygon([(x2, y2), p1, p2], fill=color)
    if label:
        fnt = label_font or font(20, italic=True)
        lx = (x1 + x2) / 2 + label_offset[0]
        ly = (y1 + y2) / 2 + label_offset[1]
        tw, th = text_size(draw, label, fnt)
        draw.rectangle((lx - tw / 2 - 8, ly - th / 2 - 4, lx + tw / 2 + 8, ly + th / 2 + 5),
                       fill="#ffffff")
        draw.text((lx - tw / 2, ly - th / 2), label, font=fnt, fill="#475569")


def make_architecture():
    W, H = 1800, 1300
    image = Image.new("RGB", (W, H), "#ffffff")
    draw = ImageDraw.Draw(image)
    draw.text((60, 35), "HÌNH 3.4. KIẾN TRÚC PIPELINE PHÁT HIỆN SỚM", font=font(34, bold=True), fill="#0f172a")
    draw.text((60, 82), "Kết hợp Suricata IDS, trích xuất đặc trưng, Ensemble Random Forest + LSTM, luật chuyên gia và chấm điểm EMA",
              font=font(21, italic=True), fill="#475569")

    # Top row
    box(draw, (50, 150, 340, 290), "Suricata EVE", "http / flow / alert\nhoặc pfSense từ xa", "#fef3c7", "#d97706")
    box(draw, (420, 150, 760, 290), "LogCollector", "Tail file, xử lý logrotate\nHàng đợi 20.000 sự kiện", "#e0f2fe", "#0284c7")
    box(draw, (840, 150, 1240, 290), "Event Worker", "Chống trùng lặp, xác định IP tấn công\nbỏ qua IP server / whitelist", "#e0f2fe", "#0284c7")
    arrow(draw, (340, 220), (420, 220), label="JSON", label_offset=(0, -24))
    arrow(draw, (760, 220), (840, 220), label="queue", label_offset=(0, -24))

    # Feature extraction
    box(draw, (420, 370, 1240, 500), "Trích xuất đặc trưng và cửa sổ trượt",
        "8 đặc trưng request + 11 đặc trưng cửa sổ (HTTP, Flow, Alert)  •  vector 19 chiều  •  N = 20 sự kiện / T = 60 giây",
        "#dcfce7", "#16a34a", title_size=29, sub_size=22)
    arrow(draw, (1040, 290), (1040, 370), label="sự kiện", label_offset=(58, 0))

    # Branch boxes
    box(draw, (250, 580, 760, 730), "Ensemble AI",
        "Random Forest (100 cây)  +  LSTM (chuỗi 5 bước)\nHợp nhất trọng số 0,5 / 0,5  →  xác suất 5 lớp",
        "#ede9fe", "#7c3aed", title_size=29, sub_size=21)
    box(draw, (900, 580, 1410, 730), "Luật chuyên gia",
        "Flow: quét cổng, flood  •  HTTP fast-track: SQLi,\nscan, brute-force, DoS  •  kiểm soát false positive",
        "#ffedd5", "#ea580c", title_size=29, sub_size=21)
    arrow(draw, (740, 500), (520, 580), label="vector 19-D", label_offset=(-70, -14))
    arrow(draw, (1060, 500), (1140, 580), label="cửa sổ", label_offset=(64, -14))

    # EMA scorer
    box(draw, (420, 810, 1240, 950), "Bộ chấm điểm phát hiện sớm (EMA)",
        "S_t = α × S_(t-1) + (1 - α) × p_t     •     α = 0,4     •     θ = 0,6     •     mức Cao ≥ 0,85\nFast detection: p_t ≥ 0,85 → cảnh báo ngay lập tức",
        "#fce7f3", "#db2777", title_size=29, sub_size=21)
    arrow(draw, (505, 730), (640, 810), label="p_t", label_offset=(-34, -18))
    arrow(draw, (1155, 730), (1020, 810), label="p_t", label_offset=(34, -18))

    # Alert manager
    box(draw, (420, 1020, 1240, 1150), "AlertManager và phản ứng",
        "Whitelist  •  cooldown 30 giây  •  ghi PostgreSQL  •  đếm ngược 5 giây  •  chặn UFW hoặc bỏ qua",
        "#fee2e2", "#dc2626", title_size=29, sub_size=21)
    arrow(draw, (830, 950), (830, 1020), label="S_t vượt ngưỡng", label_offset=(120, 0))

    # Outputs
    box(draw, (80, 1180, 830, 1275), "PostgreSQL", "events  •  alerts  •  blocked_ips  •  whitelist  •  models",
        "#e2e8f0", "#475569", title_size=26, sub_size=20)
    box(draw, (970, 1180, 1720, 1275), "SOC Dashboard", "Flask + Chart.js  •  cập nhật mỗi 1 giây  •  chặn / bỏ qua / whitelist",
        "#e2e8f0", "#475569", title_size=26, sub_size=20)
    arrow(draw, (680, 1150), (470, 1180), label="lưu vết", label_offset=(-60, -10))
    arrow(draw, (980, 1150), (1210, 1180), label="hiển thị", label_offset=(70, -10))

    image.save(os.path.join(IMG, "hinh_3_4_kien_truc.png"), quality=95)


def make_erd():
    W, H = 1800, 1220
    image = Image.new("RGB", (W, H), "#ffffff")
    draw = ImageDraw.Draw(image)
    draw.text((60, 35), "HÌNH 3.5. MÔ HÌNH QUAN HỆ THỰC THỂ CƠ SỞ DỮ LIỆU", font=font(34, bold=True), fill="#0f172a")
    draw.text((60, 82), "PostgreSQL: bảng nghiệp vụ hiện tại và bảng sự kiện mở rộng phục vụ điều tra, tái huấn luyện",
              font=font(21, italic=True), fill="#475569")

    def table_box(xy, title, rows, fill, outline, dashed=False, note=None):
        x1, y1, x2, y2 = xy
        box(draw, xy, title, None, fill, outline, radius=12, title_size=28, dashed=dashed)
        fnt = font(20)
        fnt_small = font(18, italic=True)
        y = y1 + 62
        for row in rows:
            color = "#0f172a"
            if row.endswith(" PK") or row.endswith(" FK") or row.endswith(" UQ"):
                color = "#0c4a6e"
            draw.text((x1 + 20, y), row, font=fnt, fill=color)
            y += 31
        if note:
            draw.text((x1 + 20, y + 4), note, font=fnt_small, fill="#64748b")

    table_box((50, 160, 510, 760), "events",
              ["id  BIGINT  PK", "event_uid  TEXT  UQ", "ts  TIMESTAMPTZ", "event_type  TEXT",
               "src_ip  INET", "src_port / dest_port", "dest_ip  INET", "http_method / url", "status_code  INT",
               "user_agent  TEXT", "attack_type  TEXT", "score  DOUBLE", "severity  TEXT", "raw  JSONB",
               "created_at  TIMESTAMPTZ"],
              "#f1f5f9", "#475569", dashed=True, note="Bảng mở rộng (chưa bật ghi mặc định)")
    table_box((650, 160, 1130, 720), "alerts",
              ["id  BIGINT  PK", "ts  TEXT", "src_ip  TEXT", "attack_type  TEXT", "score  DOUBLE",
               "severity  TEXT", "status  TEXT", "decided_by  TEXT", "decided_at  TEXT", "event_id  BIGINT  FK"],
              "#e0f2fe", "#0284c7", note="Chỉ mục: src_ip, status, ts")
    table_box((1270, 160, 1750, 620), "blocked_ips",
              ["id  BIGINT  PK", "ip  TEXT  UQ", "blocked_at  TEXT", "expires_at  TEXT", "reason  TEXT",
               "alert_id  BIGINT  FK", "method  TEXT", "unblocked_at  TEXT"],
              "#fee2e2", "#dc2626", note="Chỉ mục: ip")
    table_box((650, 820, 1130, 1080), "whitelist",
              ["id  BIGINT  PK", "ip  TEXT  UQ", "note  TEXT", "created_at  TEXT"],
              "#dcfce7", "#16a34a", note="Chỉ mục: ip")
    table_box((1270, 720, 1750, 1080), "models",
              ["version  TEXT  PK", "algorithm  TEXT", "trained_at  TEXT", "f1  DOUBLE", "fpr  DOUBLE",
               "path  TEXT", "is_active  SMALLINT"],
              "#fef3c7", "#d97706", note="Một phiên bản active tại một thời điểm")

    # Relations
    arrow(draw, (510, 360), (650, 360), color="#334155", width=4, label="1 : N", label_font=font(22, bold=True),
          label_offset=(0, -30), dashed=False)
    draw.text((515, 398), "event_id", font=font(17, italic=True), fill="#475569")
    arrow(draw, (1130, 380), (1270, 380), color="#334155", width=4, label="1 : N", label_font=font(22, bold=True),
          label_offset=(0, -30))
    draw.text((1140, 410), "alert_id", font=font(18, italic=True), fill="#475569")

    # Legend
    draw.rounded_rectangle((50, 1130, 1750, 1190), radius=10, fill="#f8fafc", outline="#cbd5e1", width=2)
    draw.text((75, 1147), "Chú thích:", font=font(20, bold=True), fill="#0f172a")
    draw.text((190, 1147), "PK = khóa chính   •   FK = khóa ngoại   •   UQ = ràng buộc duy nhất   •   nét đứt = thiết kế mở rộng",
              font=font(20), fill="#475569")

    image.save(os.path.join(IMG, "hinh_3_5_erd.png"), quality=95)


def make_ui():
    W, H = 1800, 990
    bg = "#0f172a"
    card = "#1e293b"
    border = "#334155"
    text = "#f8fafc"
    muted = "#94a3b8"
    blue = "#38bdf8"
    red = "#ef4444"
    yellow = "#f59e0b"
    green = "#10b981"
    purple = "#a855f7"

    image = Image.new("RGB", (W, H), bg)
    draw = ImageDraw.Draw(image)
    draw.text((60, 25), "HÌNH 3.6. BỐ CỤC GIAO DIỆN SOC DASHBOARD", font=font(34, bold=True), fill=text)
    draw.text((60, 70), "Wireframe: sidebar điều hướng, header trạng thái, 5 thẻ KPI và 4 biểu đồ thời gian thực",
              font=font(21, italic=True), fill=muted)

    # Screen frame
    sx1, sy1, sx2, sy2 = 50, 120, 1750, 960
    draw.rounded_rectangle((sx1, sy1, sx2, sy2), radius=16, fill=bg, outline=border, width=3)

    # Sidebar
    sbx1, sby1, sbx2, sby2 = sx1 + 2, sy1 + 3, sx1 + 270, sy2 - 2
    draw.rectangle((sbx1, sby1, sbx2, sby2), fill="#0b1120")
    draw.line([(sbx2, sby1), (sbx2, sby2)], fill=border, width=2)
    draw.text((sbx1 + 22, sby1 + 28), "AI-IDS SOC", font=font(25, bold=True), fill=blue)
    draw.text((sbx1 + 22, sby1 + 60), "Early Web Attack Detection", font=font(15), fill=muted)
    draw.line([(sbx1 + 20, sby1 + 95), (sbx2 - 20, sby1 + 95)], fill=border, width=1)

    navs = [("Tổng quan & Biểu đồ", True), ("Cảnh báo sớm", False),
            ("Quản lý Chặn & IP", False), ("Cấu hình Tham số", False)]
    for i, (label, active) in enumerate(navs):
        y = sby1 + 120 + i * 58
        if active:
            draw.rounded_rectangle((sbx1 + 12, y - 8, sbx2 - 12, y + 36), radius=8, fill="#1e293b")
            draw.rectangle((sbx1 + 12, y - 8, sbx1 + 16, y + 36), fill=blue)
        draw.ellipse((sbx1 + 25, y + 4, sbx1 + 41, y + 20), fill=(blue if active else muted))
        draw.text((sbx1 + 54, y), label, font=font(18, bold=active), fill=(text if active else muted))

    draw.text((sbx1 + 22, sby2 - 60), "Suricata IDS  •  PostgreSQL", font=font(15), fill=muted)

    # Header
    hx1, hy1, hx2 = sbx2 + 1, sy1 + 3, sx2 - 2
    draw.rectangle((hx1, hy1, hx2, hy1 + 72), fill="#0b1120")
    draw.line([(hx1, hy1 + 72), (hx2, hy1 + 72)], fill=border, width=2)
    draw.text((hx1 + 24, hy1 + 23), "HỆ THỐNG PHÁT HIỆN SỚM TẤN CÔNG WEB", font=font(20, bold=True), fill=text)
    # badges
    bx = hx2 - 540
    for label, color in [("Âm thanh: BẬT", muted), ("Engine: Online", green), ("Mô hình: RF + LSTM", blue)]:
        tw, th = text_size(draw, label, font(15, bold=True))
        draw.rounded_rectangle((bx, hy1 + 22, bx + tw + 24, hy1 + 52), radius=15, outline=color, width=2)
        draw.text((bx + 12, hy1 + 27), label, font=font(15, bold=True), fill=color)
        bx += tw + 38

    # Content KPI
    content_x1, content_y1 = hx1 + 18, hy1 + 90
    content_x2 = hx2 - 18
    gap = 14
    card_w = (content_x2 - content_x1 - gap * 4) / 5
    kpis = [("Collector", "Đang chạy", green), ("Mô hình AI", "RF + LSTM", blue),
            ("Sự kiện đã xử lý", "12.480", text), ("IP đang bị chặn", "07", red),
            ("pfSense Sensor", "Đang chạy", green)]
    for i, (title, value, color) in enumerate(kpis):
        x = content_x1 + i * (card_w + gap)
        draw.rounded_rectangle((x, content_y1, x + card_w, content_y1 + 82), radius=10, fill=card, outline=border, width=1)
        draw.text((x + 16, content_y1 + 14), title, font=font(15), fill=muted)
        draw.text((x + 16, content_y1 + 40), value, font=font(23, bold=True), fill=color)

    # Chart area
    chart_y = content_y1 + 100
    left_w = (content_x2 - content_x1) * 0.58
    right_x = content_x1 + left_w + 16
    draw.rounded_rectangle((content_x1, chart_y, content_x1 + left_w, chart_y + 330), radius=10, fill=card, outline=border, width=1)
    draw.text((content_x1 + 18, chart_y + 14), "Điểm bất thường tích lũy S_t (EMA Score)", font=font(18, bold=True), fill=text)
    draw.text((content_x1 + 18, chart_y + 42), "Ngưỡng θ = 0.7 (cảnh báo)  |  0.9 (nguy hiểm)", font=font(14), fill=muted)

    # line chart
    px1, py1, px2, py2 = content_x1 + 55, chart_y + 80, content_x1 + left_w - 25, chart_y + 300
    for i in range(5):
        y = py1 + i * (py2 - py1) / 4
        draw.line([(px1, y), (px2, y)], fill="#273449", width=1)
    # thresholds
    for ratio, color in [(0.3, red), (0.5, yellow)]:
        y = py2 - ratio * (py2 - py1)
        for x in range(int(px1), int(px2), 16):
            draw.line([(x, y), (x + 8, y)], fill=color, width=2)
    pts = [(px1, py2 - 0.1 * (py2 - py1)), (px1 + 70, py2 - 0.18 * (py2 - py1)),
           (px1 + 140, py2 - 0.38 * (py2 - py1)), (px1 + 210, py2 - 0.52 * (py2 - py1)),
           (px1 + 280, py2 - 0.68 * (py2 - py1)), (px1 + 350, py2 - 0.78 * (py2 - py1)),
           (px1 + 420, py2 - 0.9 * (py2 - py1))]
    draw.line(pts, fill=blue, width=4, joint="curve")
    for p in pts:
        draw.ellipse((p[0] - 4, p[1] - 4, p[0] + 4, p[1] + 4), fill=blue)

    # doughnut
    draw.rounded_rectangle((right_x, chart_y, content_x2, chart_y + 330), radius=10, fill=card, outline=border, width=1)
    draw.text((right_x + 18, chart_y + 14), "Phân bố loại tấn công", font=font(18, bold=True), fill=text)
    cx, cy, r = right_x + 150, chart_y + 185, 80
    start = -90
    values = [18, 30, 22, 16]
    colors = [blue, yellow, purple, red]
    total = sum(values)
    for val, color in zip(values, colors):
        extent = val / total * 360
        draw.pieslice((cx - r, cy - r, cx + r, cy + r), start=start, end=start + extent, fill=color)
        start += extent
    draw.ellipse((cx - 48, cy - 48, cx + 48, cy + 48), fill=card)
    draw.text((cx - 28, cy - 12), "100%", font=font(20, bold=True), fill=text)
    legend = [("Scan", blue), ("SQLi", yellow), ("Brute", purple), ("DoS", red)]
    for i, (label, color) in enumerate(legend):
        ly = chart_y + 90 + i * 42
        draw.rectangle((right_x + 290, ly, right_x + 310, ly + 18), fill=color)
        draw.text((right_x + 322, ly - 2), label, font=font(16), fill=text)

    # bottom charts
    by = chart_y + 350
    bw = (content_x2 - content_x1 - 16) / 2
    for i, title in enumerate(["Trạng thái phản ứng tự động", "Tần suất cảnh báo theo giờ"]):
        x = content_x1 + i * (bw + 16)
        draw.rounded_rectangle((x, by, x + bw, by + 205), radius=10, fill=card, outline=border, width=1)
        draw.text((x + 18, by + 14), title, font=font(17, bold=True), fill=text)
        base_y = by + 170
        for j in range(5):
            bx = x + 55 + j * 72
            h = [95, 70, 50, 30, 15][j]
            color = [red, yellow, blue, muted, green][j]
            draw.rectangle((bx, base_y - h, bx + 38, base_y), fill=color)
        draw.line([(x + 35, base_y), (x + bw - 25, base_y)], fill=border, width=2)
        labels = ["Tự chặn", "Chặn tay", "Đang chờ", "Bỏ qua", "Khác"]
        for j, label in enumerate(labels):
            draw.text((x + 48 + j * 72, base_y + 10), label, font=font(12), fill=muted)

    image.save(os.path.join(IMG, "hinh_3_6_giao_dien.png"), quality=95)


if __name__ == "__main__":
    make_architecture()
    make_erd()
    make_ui()
    print("Created figures in", IMG)
