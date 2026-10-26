"""
Module giao diện Dashboard quản trị bằng Flask (Web Dashboard) với biểu đồ tương tác thời gian thực (Chart.js).
Bao gồm đầy đủ 5 chức năng:
1. Giám sát hệ thống: Trạng thái Collector, Mô hình Ensemble (Random Forest + LSTM), Thông lượng sự kiện
2. Cảnh báo thời gian thực: Bảng cảnh báo, đếm ngược live, nút Chặn / Bỏ qua
3. Biểu đồ tương tác (Chart.js):
   - Biểu đồ đường (Line Chart): Điểm bất thường tích lũy S_t theo thời gian kèm ngưỡng cảnh báo theta
   - Biểu đồ tròn (Doughnut Chart): Phân bố tỷ lệ các loại tấn công (normal, scan, sqli, bruteforce, dos)
   - Biểu đồ cột (Bar Chart): Phân bố trạng thái xử lý cảnh báo
   - Biểu đồ đường/cột (Timeline): Xu hướng tấn công theo các khung giờ
4. Quản lý Chặn tường lửa & Whitelist IP
5. Cấu hình tham số hệ thống động (theta, alpha, N, T, thời gian chờ, trọng số Ensemble)
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Đảm bảo Python nhận diện được thư mục gốc của dự án
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from flask import Flask, jsonify, render_template_string, request
import yaml

from src.db import (
    add_to_whitelist,
    clear_alerts,
    get_active_model,
    get_alert_by_id,
    get_alerts,
    get_blocked_ips,
    get_stats,
    get_whitelist,
    init_db,
    remove_from_whitelist,
)

logger = logging.getLogger("AI_IDS.Dashboard")

app = Flask(__name__)

APP_CONTEXT: dict[str, Any] = {
    "collector": None,
    "model": None,
    "scorer": None,
    "blocker": None,
    "alert_manager": None,
    "window_tracker": None,
    "config": {},
    "config_path": "config.yaml",
    # --- THÊM MỚI: pfSense collector ---
    "pfsense_collector": None,
    # Kho dữ liệu PostgreSQL dùng cho pipeline collector -> DB -> AI worker.
    "pg_store": None,
    # Mốc bắt đầu phiên dashboard. Chỉ cảnh báo phát sinh sau mốc này được hiển
    # thị mặc định, tránh nhìn thấy lại cảnh báo cũ trong PostgreSQL.
    "session_started_at": datetime.now().isoformat(),
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Early Web Attack Detection System &bull; SOC Dashboard</title>
    <!-- Chart.js Local -->
    <script src="/static/chart.umd.min.js"></script>
    <style>
        :root {
            --bg-main: #0f172a;
            --bg-card: #1e293b;
            --bg-sidebar: #0b1120;
            --border-color: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-blue: #38bdf8;
            --accent-red: #ef4444;
            --accent-yellow: #f59e0b;
            --accent-green: #10b981;
            --accent-purple: #a855f7;
        }

        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            margin: 0;
            background: var(--bg-main);
            color: var(--text-main);
            display: flex;
            height: 100vh;
            overflow: hidden;
        }

        /* Sidebar */
        aside {
            width: 240px;
            background: var(--bg-sidebar);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            padding: 20px 0;
        }
        .brand {
            padding: 0 20px 20px 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .brand h2 {
            font-size: 1.05rem;
            margin: 0;
            color: var(--accent-blue);
            font-weight: 700;
        }
        .nav-links {
            list-style: none;
            margin: 20px 0 0 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .nav-btn {
            width: 100%;
            padding: 12px 20px;
            background: none;
            border: none;
            color: var(--text-muted);
            text-align: left;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 12px;
            transition: all 0.2s;
        }
        .nav-btn:hover, .nav-btn.active {
            background: #1e293b;
            color: var(--accent-blue);
            border-left: 3px solid var(--accent-blue);
        }

        /* Main Content */
        main {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
        }
        header {
            height: 60px;
            background: var(--bg-card);
            border-bottom: 1px solid var(--border-color);
            padding: 0 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .content-area {
            padding: 20px 24px;
            flex: 1;
        }

        /* Metric Cards */
        .grid-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            position: relative;
        }
        .card-title {
            font-size: 0.78rem;
            color: var(--text-muted);
            text-transform: uppercase;
            font-weight: 700;
            letter-spacing: 0.5px;
            margin-bottom: 6px;
        }
        .card-value {
            font-size: 1.6rem;
            font-weight: 700;
            color: var(--text-main);
        }

        /* Charts Grid */
        .grid-charts {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 16px;
            margin-bottom: 20px;
        }
        @media (max-width: 1024px) {
            .grid-charts { grid-template-columns: 1fr; }
        }
        .chart-box {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 18px;
        }
        .chart-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .chart-header h3 {
            margin: 0;
            font-size: 0.95rem;
            color: var(--accent-blue);
        }

        /* Table */
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.88rem;
            margin-top: 10px;
        }
        th, td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        th {
            background: #0f172a;
            color: var(--text-muted);
            font-weight: 600;
        }
        tr:hover { background: #1b263b; }

        /* Badges */
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.72rem;
            font-weight: 700;
        }
        .badge-danger { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4); }
        .badge-warning { background: rgba(245, 158, 11, 0.2); color: #fcd34d; border: 1px solid rgba(245, 158, 11, 0.4); }
        .badge-success { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.4); }
        .badge-info { background: rgba(56, 189, 248, 0.2); color: #7dd3fc; border: 1px solid rgba(56, 189, 248, 0.4); }

        /* Buttons */
        .btn {
            padding: 6px 12px;
            font-size: 0.8rem;
            border-radius: 4px;
            border: none;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.15s;
        }
        .btn-danger { background: var(--accent-red); color: #fff; }
        .btn-danger:hover { opacity: 0.85; }
        .btn-secondary { background: #475569; color: #fff; }
        .btn-secondary:hover { background: #64748b; }
        .btn-primary { background: var(--accent-blue); color: #0b1120; font-weight: 700; }
        .btn-success { background: var(--accent-green); color: #0b1120; font-weight: 700; }

        .countdown {
            font-weight: bold;
            color: var(--accent-yellow);
            animation: pulse 1s infinite alternate;
        }
        @keyframes pulse { from { opacity: 0.6; } to { opacity: 1; } }

        .tab-pane { display: none; }
        .tab-pane.active { display: block; }

        /* Form */
        .form-group { margin-bottom: 14px; }
        .form-group label { display: block; font-size: 0.85rem; margin-bottom: 5px; color: var(--text-muted); }
        .form-group input {
            width: 100%;
            max-width: 420px;
            padding: 8px 12px;
            background: #0f172a;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            color: var(--text-main);
        }
    </style>
</head>
<body>

    <!-- Sidebar -->
    <aside>
        <div class="brand">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <h2>AI-IDS SOC</h2>
        </div>
        <ul class="nav-links">
            <li><button class="nav-btn active" onclick="switchTab('tab-overview')">📊 Tổng quan & Biểu đồ</button></li>
            <li><button class="nav-btn" onclick="switchTab('tab-alerts')">🚨 Cảnh báo sớm</button></li>
            <li><button class="nav-btn" onclick="switchTab('tab-blocked')">🛡️ Quản lý Chặn & IP</button></li>
            <li><button class="nav-btn" onclick="switchTab('tab-config')">⚙️ Cấu hình Tham số</button></li>
        </ul>
    </aside>

    <!-- Main -->
    <main>
        <header>
            <div style="font-weight: 600; font-size: 0.95rem;">HỆ THỐNG PHÁT HIỆN SỚM TẤN CÔNG WEB (SURICATA + ENSEMBLE LSTM & RF)</div>
            <div style="display: flex; gap: 10px; align-items: center;">
                <button id="btn-sound-toggle" onclick="toggleSound()" class="btn btn-secondary" style="display:flex; align-items:center; gap:6px; font-weight:600; cursor:pointer;">
                    🔊 Âm thanh: BẬT
                </button>
                <span class="badge badge-success" id="hdr-engine">Engine: Online</span>
                <span class="badge badge-info" id="hdr-model">Mô hình: RF + LSTM</span>
            </div>
        </header>

        <!-- Banner cảnh báo tức thời nổi bật -->
        <div id="live-alert-banner" style="display:none; background: linear-gradient(90deg, #ef4444, #b91c1c); color: white; padding: 12px 20px; margin: 12px 20px 0 20px; border-radius: 6px; font-weight: bold; animation: pulse 0.8s infinite alternate; align-items: center; justify-content: space-between; box-shadow: 0 4px 15px rgba(239, 68, 68, 0.4);">
            <div style="display:flex; align-items:center; gap:10px;">
                <span style="font-size:1.3rem;">🚨</span>
                <span id="live-alert-text">PHÁT HIỆN CẢNH BÁO TẤN CÔNG!</span>
            </div>
            <button onclick="document.getElementById('live-alert-banner').style.display='none'" style="background:rgba(255,255,255,0.2); border:none; color:white; font-size:0.9rem; padding:4px 10px; border-radius:4px; cursor:pointer;">Đóng</button>
        </div>

        <div class="content-area">
            <!-- Thống kê đầu trang -->
            <div class="grid-cards">
                <div class="card">
                    <div class="card-title">Bộ thu thập Log (Collector)</div>
                    <div class="card-value" id="stat-collector" style="font-size: 1.25rem;">Đang chạy</div>
                </div>
                <div class="card">
                    <div class="card-title">Mô hình AI Ensemble</div>
                    <div class="card-value" id="stat-model" style="font-size: 1.25rem; color: var(--accent-blue);">RF + LSTM</div>
                </div>
                <div class="card">
                    <div class="card-title">Sự kiện đã xử lý</div>
                    <div class="card-value" id="stat-events">0</div>
                    <div id="stat-events-sub" style="font-size: 0.75rem; color: var(--text-muted);"></div>
                </div>
                <div class="card">
                    <div class="card-title">Hàng đợi AI (PostgreSQL)</div>
                    <div class="card-value" id="stat-queue" style="color: var(--accent-yellow);">0</div>
                    <div id="stat-queue-sub" style="font-size: 0.75rem; color: var(--text-muted);"></div>
                </div>
                <div class="card">
                    <div class="card-title">Dự đoán AI</div>
                    <div class="card-value" id="stat-predictions" style="color: var(--accent-purple);">0</div>
                    <div id="stat-predictions-sub" style="font-size: 0.75rem; color: var(--text-muted);"></div>
                </div>
                <div class="card">
                    <div class="card-title">IP Đang Bị Chặn (UFW)</div>
                    <div class="card-value" id="stat-blocked" style="color: var(--accent-red);">0</div>
                </div>
                <div class="card">
                    <div class="card-title">pfSense / Suricata Sensor</div>
                    <div class="card-value" id="stat-pfsense" style="font-size: 1.1rem; color: var(--accent-green);">TẮT</div>
                    <div id="stat-pfsense-sub" style="font-size: 0.75rem; color: var(--text-muted);"></div>
                </div>
            </div>

            <!-- TAB 1: TỔNG QUAN & BIỂU ĐỒ -->
            <div id="tab-overview" class="tab-pane active">
                <div class="grid-charts">
                    <!-- Biểu đồ đường S_t -->
                    <div class="chart-box">
                        <div class="chart-header">
                            <h3>Biểu đồ Điểm Bất Thường Tích Lũy S_t (EMA Score) theo Thời Gian</h3>
                            <span style="font-size: 0.75rem; color: var(--text-muted);">Ngưỡng &theta; = 0.7 (Cảnh báo) | 0.9 (Nguy hiểm)</span>
                        </div>
                        <div style="height: 260px;">
                            <canvas id="scoreLineChart"></canvas>
                        </div>
                    </div>

                    <!-- Biểu đồ phân bố tấn công (Doughnut) -->
                    <div class="chart-box">
                        <div class="chart-header">
                            <h3>Phân Bố Loại Tấn Công</h3>
                        </div>
                        <div style="height: 260px;">
                            <canvas id="attackDoughnutChart"></canvas>
                        </div>
                    </div>
                </div>

                <div class="grid-charts" style="grid-template-columns: 1fr 1fr;">
                    <!-- Biểu đồ trạng thái xử lý (Bar) -->
                    <div class="chart-box">
                        <div class="chart-header">
                            <h3>Trạng Thái Phản Ứng Tự Động (Defense Actions)</h3>
                        </div>
                        <div style="height: 220px;">
                            <canvas id="statusStatusBarChart"></canvas>
                        </div>
                    </div>

                    <!-- Biểu đồ xu hướng sự kiện theo giờ -->
                    <div class="chart-box">
                        <div class="chart-header">
                            <h3>Tần Suất Cảnh Báo Theo Giờ</h3>
                        </div>
                        <div style="height: 220px;">
                            <canvas id="timelineChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>

            <!-- TAB 2: CẢNH BÁO THỜI GIAN THỰC -->
            <div id="tab-alerts" class="tab-pane">
                <div class="chart-box">
                    <div class="chart-header">
                        <h3>Bảng Theo Dõi Cảnh Báo Phát Hiện Sớm</h3>
                        <div style="display:flex; align-items:center; gap:12px;">
                            <span id="alert-scope-note" style="font-size:0.8rem; color:var(--text-muted);">Chỉ cảnh báo phát sinh trong phiên chạy này</span>
                            <button class="btn btn-secondary" id="btn-alert-history" onclick="toggleAlertHistory()">Hiện cảnh báo cũ</button>
                            <button class="btn btn-secondary" onclick="clearAlerts()">Xóa cảnh báo cũ</button>
                        </div>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Thời gian</th>
                                <th>IP Nguồn</th>
                                <th>Loại Tấn Công</th>
                                <th>Điểm S_t</th>
                                <th>Mức Độ</th>
                                <th>Trạng Thái</th>
                                <th>Đếm Ngược</th>
                                <th>Hành Động</th>
                            </tr>
                        </thead>
                        <tbody id="tbody-alerts">
                            <tr><td colspan="9" style="text-align:center;">Đang nạp dữ liệu...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- TAB 3: QUẢN LÝ CHẶN & WHITELIST -->
            <div id="tab-blocked" class="tab-pane">
                <div class="chart-box" style="margin-bottom: 20px;">
                    <div class="chart-header">
                        <h3>Danh Sách IP Đang Bị Chặn Trên Tường Lửa UFW</h3>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>IP Nguồn</th>
                                <th>Thời Gian Chặn</th>
                                <th>Hết Hạn</th>
                                <th>Lý Do</th>
                                <th>Phương Thức</th>
                                <th>Hành Động</th>
                            </tr>
                        </thead>
                        <tbody id="tbody-blocked">
                            <tr><td colspan="7" style="text-align:center;">Không có IP bị chặn</td></tr>
                        </tbody>
                    </table>
                </div>

                <div class="chart-box">
                    <div class="chart-header">
                        <h3>Danh Sách IP Tin Cậy (Whitelist - Không Bao Giờ Chặn)</h3>
                    </div>
                    <div style="display:flex; gap:10px; margin-bottom: 15px; align-items: flex-end;">
                        <div class="form-group" style="margin-bottom:0;">
                            <label>Địa chỉ IP:</label>
                            <input type="text" id="wl-ip" placeholder="192.168.1.1">
                        </div>
                        <div class="form-group" style="margin-bottom:0;">
                            <label>Ghi chú:</label>
                            <input type="text" id="wl-note" placeholder="Gateway pfSense">
                        </div>
                        <button class="btn btn-primary" onclick="addWhitelist()" style="height:36px;">Thêm Whitelist</button>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Địa Chỉ IP</th>
                                <th>Ghi Chú</th>
                                <th>Ngày Tạo</th>
                                <th>Hành Động</th>
                            </tr>
                        </thead>
                        <tbody id="tbody-whitelist">
                            <tr><td colspan="5" style="text-align:center;">Đang tải whitelist...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- TAB 4: CẤU HÌNH THAM SỐ -->
            <div id="tab-config" class="tab-pane">
                <div class="chart-box">
                    <div class="chart-header">
                        <h3>Cấu Hình Tham Số Phát Hiện Sớm & Mô Hình AI</h3>
                    </div>
                    <form id="config-form" onsubmit="saveConfig(event)">
                        <div class="form-group">
                            <label>Ngưỡng cảnh báo &theta; (theta) [Mặc định 0.7]:</label>
                            <input type="number" step="0.05" min="0.1" max="1.0" id="cfg-theta" required>
                        </div>
                        <div class="form-group">
                            <label>Hệ số làm mịn tích lũy &alpha; (alpha) [Mặc định 0.7]:</label>
                            <input type="number" step="0.05" min="0.1" max="0.95" id="cfg-alpha" required>
                        </div>
                        <div class="form-group">
                            <label>Kích thước cửa sổ trượt N sự kiện (window_size_n):</label>
                            <input type="number" min="5" max="100" id="cfg-n" required>
                        </div>
                        <div class="form-group">
                            <label>Thời gian cửa sổ trượt T giây (window_time_t):</label>
                            <input type="number" min="10" max="600" id="cfg-t" required>
                        </div>
                        <div class="form-group">
                            <label>Thời gian đếm ngược trước khi tự động chặn (giây):</label>
                            <input type="number" min="1" max="60" id="cfg-countdown" required>
                        </div>
                        <div class="form-group">
                            <label>Đường dẫn log Suricata EVE JSON:</label>
                            <input type="text" id="cfg-logpath" required>
                        </div>
                        <button type="submit" class="btn btn-success" style="padding: 10px 20px;">Lưu Cấu Hình</button>
                        <span id="cfg-save-msg" style="margin-left:15px; color:var(--accent-green); font-weight:bold;"></span>
                    </form>
                </div>
            </div>
        </div>
    </main>

    <script>
        function switchTab(tabId) {
            document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            event.currentTarget.classList.add('active');

            if (tabId === 'tab-blocked') loadBlockedAndWhitelist();
            if (tabId === 'tab-config') loadConfig();
            if (tabId === 'tab-overview') updateCharts();
        }

        // --- KHỞI TẠO BIỂU ĐỒ CHART.JS ---
        let lineChart = null;
        let doughnutChart = null;
        let barChart = null;
        let timelineChart = null;

        function initCharts() {
            // 1. Line Chart
            const ctxLine = document.getElementById('scoreLineChart').getContext('2d');
            lineChart = new Chart(ctxLine, {
                type: 'line',
                data: {
                    labels: ['-10s', '-8s', '-6s', '-4s', '-2s', 'Hiện tại'],
                    datasets: [
                        {
                            label: 'IP Đang Theo Dõi (S_t)',
                            data: [0, 0, 0, 0, 0, 0],
                            borderColor: '#38bdf8',
                            backgroundColor: 'rgba(56, 189, 248, 0.1)',
                            fill: true,
                            tension: 0.3,
                            borderWidth: 2
                        },
                        {
                            label: 'Ngưỡng Cảnh Báo Theta (0.7)',
                            data: [0.7, 0.7, 0.7, 0.7, 0.7, 0.7],
                            borderColor: '#f59e0b',
                            borderDash: [5, 5],
                            pointRadius: 0,
                            fill: false
                        },
                        {
                            label: 'Ngưỡng Nguy Hiểm Cao (0.9)',
                            data: [0.9, 0.9, 0.9, 0.9, 0.9, 0.9],
                            borderColor: '#ef4444',
                            borderDash: [4, 4],
                            pointRadius: 0,
                            fill: false
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { min: 0, max: 1.0, grid: { color: '#334155' }, ticks: { color: '#94a3b8' } },
                        x: { grid: { color: '#334155' }, ticks: { color: '#94a3b8' } }
                    },
                    plugins: { legend: { labels: { color: '#f8fafc', font: { size: 11 } } } }
                }
            });

            // 2. Doughnut Chart
            const ctxDoughnut = document.getElementById('attackDoughnutChart').getContext('2d');
            doughnutChart = new Chart(ctxDoughnut, {
                type: 'doughnut',
                data: {
                    labels: ['Normal', 'Scan', 'SQLi', 'Bruteforce', 'DoS'],
                    datasets: [{
                        data: [0, 0, 0, 0, 0],
                        backgroundColor: ['#10b981', '#38bdf8', '#f59e0b', '#a855f7', '#ef4444'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'bottom', labels: { color: '#f8fafc', font: { size: 10 } } } }
                }
            });

            // 3. Bar Chart (Status)
            const ctxBar = document.getElementById('statusStatusBarChart').getContext('2d');
            barChart = new Chart(ctxBar, {
                type: 'bar',
                data: {
                    labels: ['Tự động chặn', 'Chặn thủ công', 'Đang chờ', 'Đã bỏ qua'],
                    datasets: [{
                        label: 'Số lượng',
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#ef4444', '#f59e0b', '#38bdf8', '#64748b'],
                        borderRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true, grid: { color: '#334155' }, ticks: { color: '#94a3b8', stepSize: 1 } },
                        x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
                    },
                    plugins: { legend: { display: false } }
                }
            });

            // 4. Timeline Chart
            const ctxTimeline = document.getElementById('timelineChart').getContext('2d');
            timelineChart = new Chart(ctxTimeline, {
                type: 'bar',
                data: {
                    labels: ['H-4', 'H-3', 'H-2', 'H-1', 'Bây giờ'],
                    datasets: [{
                        label: 'Cảnh báo',
                        data: [0, 0, 0, 0, 0],
                        backgroundColor: '#a855f7',
                        borderRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true, grid: { color: '#334155' }, ticks: { color: '#94a3b8', stepSize: 1 } },
                        x: { grid: { color: '#334155' }, ticks: { color: '#94a3b8' } }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        }

        // --- FETCH DỮ LIỆU ---
        async function fetchStatus() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();
                document.getElementById('stat-collector').innerText = data.collector_status;
                document.getElementById('stat-model').innerText = data.model_status;
                document.getElementById('stat-events').innerText = data.processed_events;
                document.getElementById('stat-blocked').innerText = data.blocked_count;

                const pipe = data.pipeline || {};
                const evSub = document.getElementById('stat-events-sub');
                if (evSub) {
                    evSub.innerText = `Nhận: ${pipe.raw_total || 0} | Lỗi: ${pipe.raw_failed || 0}`;
                }
                const queueEl = document.getElementById('stat-queue');
                const queueSub = document.getElementById('stat-queue-sub');
                if (queueEl) queueEl.innerText = pipe.raw_pending || 0;
                if (queueSub) {
                    queueSub.innerText = (pipe.raw_processing ? `Đang xử lý: ${pipe.raw_processing}` : 'Chờ Worker AI')
                        + (pipe.last_event_at ? ` | Mới nhất: ${pipe.last_event_at.substring(11, 19)}` : '');
                }
                const predEl = document.getElementById('stat-predictions');
                const predSub = document.getElementById('stat-predictions-sub');
                if (predEl) predEl.innerText = pipe.predictions_total || 0;
                if (predSub) {
                    predSub.innerText = `Features: ${pipe.features_total || 0} | Cảnh báo: ${pipe.alerts_total || 0}`;
                }
                const pf = data.pfsense;
                const pfEl = document.getElementById('stat-pfsense');
                const pfSub = document.getElementById('stat-pfsense-sub');
                if (pfEl) {
                    if (!pf) { pfEl.innerText = 'TẮT'; if (pfSub) pfSub.innerText = 'Không có collector pfSense trong tiến trình này'; }
                    else if (pf.running) { pfEl.innerText = 'Đang chạy (' + pf.host + ')'; if (pfSub) pfSub.innerText = 'sync: ' + (pf.last_sync || '...') + ' | batch: ' + pf.synced_batches; }
                    else { pfEl.innerText = pf.last_error ? 'Loi ket noi' : 'Da dung'; if (pfSub) pfSub.innerText = pf.last_error || pf.message || ''; }
                }
            } catch (e) {
                console.error("Lỗi fetch status:", e);
            }
        }

        async function updateCharts() {
            try {
                const res = await fetch('/api/stats' + alertScopeQuery());
                const data = await res.json();

                // Cập nhật Doughnut
                if (doughnutChart && data.by_type) {
                    const labels = ['normal', 'scan', 'sqli', 'bruteforce', 'dos'];
                    const vals = labels.map(l => data.by_type[l] || 0);
                    doughnutChart.data.datasets[0].data = vals;
                    doughnutChart.update();
                }

                // Cập nhật Bar Status
                if (barChart && data.by_status) {
                    const statusVals = [
                        data.by_status['auto_blocked'] || 0,
                        data.by_status['manual_blocked'] || 0,
                        data.by_status['pending'] || 0,
                        data.by_status['ignored'] || 0
                    ];
                    barChart.data.datasets[0].data = statusVals;
                    barChart.update();
                }

                // Cập nhật Timeline
                if (timelineChart) {
                    if (data.time_series && data.time_series.length > 0) {
                        const tLabels = data.time_series.map(t => t.time.slice(-5)).reverse();
                        const tCounts = data.time_series.map(t => t.count).reverse();
                        timelineChart.data.labels = tLabels;
                        timelineChart.data.datasets[0].data = tCounts;
                    } else {
                        timelineChart.data.labels = ['-4h', '-3h', '-2h', '-1h', 'Bây giờ'];
                        timelineChart.data.datasets[0].data = [0, 0, 0, 0, 0];
                    }
                    timelineChart.update();
                }
            } catch (e) {
                console.error("Lỗi cập nhật biểu đồ:", e);
            }
        }

        // --- BỘ TỔNG HỢP ÂM THANH CẢNH BÁO AN NINH (WEB AUDIO API SYNTHESIZER) ---
        let audioCtx = null;
        let isSoundEnabled = localStorage.getItem('ids_sound_enabled') !== 'false';
        let lastSeenAlertId = -1;
        let showAlertHistory = false;

        function alertScopeQuery() {
            return showAlertHistory ? '?include_history=1' : '';
        }

        function toggleAlertHistory() {
            showAlertHistory = !showAlertHistory;
            // Đặt lại mốc để không phát âm thanh cho loạt cảnh báo cũ vừa hiện ra
            lastSeenAlertId = -1;
            const btn = document.getElementById('btn-alert-history');
            const note = document.getElementById('alert-scope-note');
            if (btn) btn.innerText = showAlertHistory ? 'Chỉ hiện phiên này' : 'Hiện cảnh báo cũ';
            if (note) {
                note.innerText = showAlertHistory
                    ? 'Đang xem toàn bộ lịch sử cảnh báo trong PostgreSQL'
                    : 'Chỉ cảnh báo phát sinh trong phiên chạy này';
            }
            fetchAlerts();
            updateCharts();
        }

        function updateSoundButton() {
            const btn = document.getElementById('btn-sound-toggle');
            if (!btn) return;
            if (isSoundEnabled) {
                btn.innerHTML = '🔊 Âm thanh: BẬT';
                btn.style.color = '#10b981';
                btn.style.borderColor = '#10b981';
            } else {
                btn.innerHTML = '🔇 Âm thanh: TẮT';
                btn.style.color = '#94a3b8';
                btn.style.borderColor = '#334155';
            }
        }

        function toggleSound() {
            isSoundEnabled = !isSoundEnabled;
            localStorage.setItem('ids_sound_enabled', isSoundEnabled ? 'true' : 'false');
            updateSoundButton();
            if (isSoundEnabled) {
                playSecurityAlertSound('test', 'Trung bình');
            }
        }

        function initAudio() {
            if (!audioCtx) {
                const AudioCtx = window.AudioContext || window.webkitAudioContext;
                if (AudioCtx) {
                    audioCtx = new AudioCtx();
                }
            }
            if (audioCtx && audioCtx.state === 'suspended') {
                audioCtx.resume();
            }
        }
        document.addEventListener('click', () => { initAudio(); }, { once: true });

        function playSecurityAlertSound(attackType, severity) {
            if (!isSoundEnabled) return;
            try {
                initAudio();
                if (!audioCtx) return;

                const now = audioCtx.currentTime;
                // Tone 1: Âm còi hú cảnh báo 880Hz -> 1320Hz
                const osc1 = audioCtx.createOscillator();
                const gain1 = audioCtx.createGain();
                osc1.type = 'sawtooth';
                osc1.frequency.setValueAtTime(880, now);
                osc1.frequency.exponentialRampToValueAtTime(1320, now + 0.15);

                gain1.gain.setValueAtTime(0.2, now);
                gain1.gain.exponentialRampToValueAtTime(0.01, now + 0.3);

                osc1.connect(gain1);
                gain1.connect(audioCtx.destination);
                osc1.start(now);
                osc1.stop(now + 0.3);

                // Tone 2: Tiếng bíp bíp sắc nét tần số cao sau 0.32s
                setTimeout(() => {
                    if (!audioCtx) return;
                    const now2 = audioCtx.currentTime;
                    const osc2 = audioCtx.createOscillator();
                    const gain2 = audioCtx.createGain();
                    osc2.type = 'sine';
                    osc2.frequency.setValueAtTime(1100, now2);
                    osc2.frequency.exponentialRampToValueAtTime(1400, now2 + 0.18);

                    gain2.gain.setValueAtTime(0.25, now2);
                    gain2.gain.exponentialRampToValueAtTime(0.01, now2 + 0.22);

                    osc2.connect(gain2);
                    gain2.connect(audioCtx.destination);
                    osc2.start(now2);
                    osc2.stop(now2 + 0.22);
                }, 320);
            } catch (e) {
                console.warn("Lỗi phát âm thanh cảnh báo:", e);
            }
        }

        async function fetchAlerts() {
            try {
                const res = await fetch('/api/alerts' + alertScopeQuery());
                const data = await res.json();
                const tbody = document.getElementById('tbody-alerts');

                if (!data.alerts || data.alerts.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color:#94a3b8;">Chưa có cảnh báo nào</td></tr>';
                    // Không còn cảnh báo trong phạm vi đang xem -> đưa biểu đồ S_t về 0
                    if (lineChart) {
                        lineChart.data.datasets[0].data = [0, 0, 0, 0, 0, 0];
                        lineChart.update();
                    }
                    return;
                }

                // Phát hiện cảnh báo mới -> Phát âm thanh & hiển thị Banner
                const alertIds = data.alerts.map(a => a.id);
                const maxId = Math.max(...alertIds);
                if (lastSeenAlertId === -1) {
                    lastSeenAlertId = maxId;
                } else if (maxId > lastSeenAlertId) {
                    const newAlert = data.alerts.find(a => a.id === maxId) || data.alerts[0];
                    lastSeenAlertId = maxId;

                    // PHÁT ÂM THANH CẢNH BÁO
                    playSecurityAlertSound(newAlert.attack_type, newAlert.severity);

                    // HIỂN THỊ BANNER TOAST NỔI BẬT
                    const banner = document.getElementById('live-alert-banner');
                    const text = document.getElementById('live-alert-text');
                    if (banner && text) {
                        text.innerHTML = `🚨 PHÁT HIỆN TẤN CÔNG [${(newAlert.attack_type || 'unknown').toUpperCase()}] từ IP: ${newAlert.src_ip} | Điểm EMA: ${Number(newAlert.score || 0).toFixed(4)} (${newAlert.severity || '-'})`;
                        banner.style.display = 'flex';
                        // Tự ẩn banner sau 10 giây để không gây cảm giác "vẫn đang bị tấn công"
                        clearTimeout(window.__alertBannerTimer);
                        window.__alertBannerTimer = setTimeout(() => {
                            banner.style.display = 'none';
                        }, 10000);
                    }
                }

                // Cập nhật điểm Line Chart từ alert gần nhất
                if (lineChart && data.alerts.length > 0) {
                    const recentScores = data.alerts.slice(0, 6).map(a => Number(a.score || 0)).reverse();
                    if (recentScores.length > 0) {
                        lineChart.data.datasets[0].data = recentScores;
                        lineChart.update();
                    }
                }

                let html = '';
                for (const a of data.alerts) {
                    const cd = data.countdowns[a.id];
                    const scoreVal = Number(a.score || 0);
                    const tsRaw = a.ts || a.alert_timestamp || a.created_at || '';
                    const tsText = tsRaw
                        ? String(tsRaw).replace('T', ' ').replace('Z', '').substring(0, 19)
                        : '-';
                    const attackType = (a.attack_type || 'unknown').toUpperCase();
                    const severity = a.severity || '-';
                    let cdHtml = '-';
                    let actionHtml = '-';

                    if (a.status === 'pending') {
                        cdHtml = cd ? `<span class="countdown">${cd}s</span>` : '0s';
                        actionHtml = `
                            <button class="btn btn-danger" onclick="blockAlert(${a.id})">Chặn</button>
                            <button class="btn btn-secondary" onclick="ignoreAlert(${a.id})">Bỏ qua</button>
                        `;
                    } else if (a.status === 'new') {
                        actionHtml = `
                            <button class="btn btn-danger" onclick="blockAlert(${a.id})">Chặn</button>
                            <button class="btn btn-secondary" onclick="ignoreAlert(${a.id})">Bỏ qua</button>
                        `;
                    } else if (a.status === 'auto_blocked') {
                        actionHtml = '<span class="badge badge-danger">Tự chặn</span>';
                    } else if (a.status === 'manual_blocked') {
                        actionHtml = '<span class="badge badge-warning">Chặn tay</span>';
                    } else if (a.status === 'ignored' || a.status === 'false_positive') {
                        actionHtml = '<span class="badge badge-info">Cảnh báo nhầm</span>';
                    } else if (a.status === 'confirmed') {
                        actionHtml = '<span class="badge badge-success">Đã xác nhận</span>';
                    } else if (a.status === 'alerted') {
                        actionHtml = `
                            <span class="badge badge-warning">⚠️ Cảnh báo</span>
                            <button class="btn btn-danger" style="margin-left:6px; padding:3px 8px;" onclick="blockAlert(${a.id})">Chặn tay</button>
                        `;
                    }

                    const sevBadge = /cao|high|critical/i.test(severity) ? 'badge-danger' : 'badge-warning';
                    const statusLabels = {
                        new: 'Mới',
                        alerted: 'Cảnh báo',
                        confirmed: 'Đã xác nhận',
                        false_positive: 'Cảnh báo nhầm',
                        pending: 'Đang chờ',
                        auto_blocked: 'Tự động chặn',
                        manual_blocked: 'Chặn thủ công',
                        ignored: 'Đã bỏ qua'
                    };
                    const statusLabel = statusLabels[a.status] || a.status || '-';
                    const detailBtn = `<button class="btn btn-secondary" style="margin-left:6px; padding:3px 8px;" onclick="showAlertDetail(${a.id})">Chi tiết</button>`;

                    html += `<tr>
                        <td>#${a.id}</td>
                        <td style="font-size:0.75rem; color:#94a3b8;">${tsText}</td>
                        <td><strong>${a.src_ip}</strong></td>
                        <td><span class="badge badge-info">${attackType}</span></td>
                        <td><strong>${scoreVal.toFixed(4)}</strong></td>
                        <td><span class="badge ${sevBadge}">${severity}</span></td>
                        <td>${statusLabel}</td>
                        <td>${cdHtml}</td>
                        <td>${actionHtml}${detailBtn}</td>
                    </tr>`;
                }
                tbody.innerHTML = html;
            } catch (e) {
                console.error("Lỗi nạp cảnh báo:", e);
            }
        }

        async function blockAlert(id) {
            await fetch(`/api/alerts/${id}/block`, { method: 'POST' });
            fetchAlerts();
            fetchStatus();
            updateCharts();
        }

        async function ignoreAlert(id) {
            await fetch(`/api/alerts/${id}/ignore`, { method: 'POST' });
            fetchAlerts();
            updateCharts();
        }

        async function showAlertDetail(id) {
            const modal = document.getElementById('alert-detail-modal');
            const body = document.getElementById('alert-detail-body');
            body.innerText = 'Đang tải hồ sơ bằng chứng...';
            modal.style.display = 'flex';
            try {
                const res = await fetch(`/api/alerts/${id}/detail`);
                const data = await res.json();
                if (!res.ok) {
                    body.innerText = data.message || 'Không tải được chi tiết cảnh báo';
                    return;
                }
                const a = data.alert || {};
                const ev = data.raw_event || {};
                const lines = [];
                lines.push(`CẢNH BÁO #${a.id}  |  ${(a.attack_type || '').toUpperCase()}  |  ${a.severity}`);
                lines.push(`Thời gian     : ${String(a.ts || a.alert_timestamp || a.created_at || '-').replace('T', ' ').replace('Z', '').substring(0, 19)}`);
                lines.push(`Nguồn -> Đích : ${a.src_ip} -> ${a.dest_ip || '-'}`);
                lines.push(`Điểm EMA S_t  : ${Number(a.score || 0).toFixed(4)}   | Độ tin cậy: ${Number(a.confidence || 0).toFixed(4)}`);
                lines.push(`Nguồn phát hiện: ${a.source_of_detection || '-'}   | Trạng thái: ${a.status}`);
                lines.push('');
                lines.push('--- WEB INDICATORS ---');
                const web = (data.evidence && data.evidence.web_indicators) || {};
                lines.push(`URL          : ${web.url || '-'}`);
                lines.push(`Method/Status: ${web.http_method || '-'} / ${web.status || '-'}`);
                lines.push(`User-Agent   : ${web.user_agent || '-'}`);
                lines.push(`Hostname     : ${web.hostname || '-'}`);
                lines.push('');
                lines.push('--- SURICATA ---');
                const suri = (data.evidence && data.evidence.suricata) || {};
                lines.push(`Signature    : ${suri.signature || '-'}`);
                lines.push(`Category     : ${suri.category || '-'}   | Severity: ${suri.severity ?? '-'}`);
                lines.push('');
                lines.push('--- AI PREDICTIONS (PostgreSQL) ---');
                if (data.predictions && data.predictions.length) {
                    for (const p of data.predictions) {
                        lines.push(`• ${p.model_name}: ${p.predicted_label} | confidence=${Number(p.confidence || 0).toFixed(4)} | risk=${p.risk_level} | ${Number(p.inference_latency_ms || 0).toFixed(2)}ms`);
                    }
                } else {
                    lines.push('(không có bản ghi ai_predictions)');
                }
                lines.push('');
                lines.push(`--- RAW EVENT #${ev.id || (data.evidence && data.evidence.event_id) || '-'} ---`);
                if (ev.raw_json) {
                    lines.push(JSON.stringify(ev.raw_json, null, 2));
                } else if (data.evidence) {
                    lines.push(JSON.stringify(data.evidence, null, 2));
                }
                body.innerText = lines.join('\\n');
            } catch (e) {
                body.innerText = 'Lỗi tải chi tiết: ' + e;
            }
        }

        function closeAlertDetail() {
            document.getElementById('alert-detail-modal').style.display = 'none';
        }

        async function clearAlerts() {
            if (!confirm('Xoá toàn bộ cảnh báo trong CSDL? Hành động này không thể hoàn tác.')) return;
            const res = await fetch('/api/alerts/clear', { method: 'POST' });
            const data = await res.json();
            lastSeenAlertId = -1;
            alert(data.message || 'Đã xoá cảnh báo');
            fetchAlerts();
            fetchStatus();
            updateCharts();
        }

        async function loadBlockedAndWhitelist() {
            try {
                const resB = await fetch('/api/blocked');
                const dataB = await resB.json();
                const tbodyB = document.getElementById('tbody-blocked');
                if (dataB.length === 0) {
                    tbodyB.innerHTML = '<tr><td colspan="7" style="text-align:center; color:#94a3b8;">Không có IP bị chặn</td></tr>';
                } else {
                    let hB = '';
                    for (const b of dataB) {
                        hB += `<tr>
                            <td>#${b.id}</td>
                            <td><strong style="color:var(--accent-red);">${b.ip}</strong></td>
                            <td style="font-size:0.75rem;">${(b.blocked_at||'').replace('T', ' ').substring(0, 19)}</td>
                            <td style="font-size:0.75rem;">${(b.expires_at||'').replace('T', ' ').substring(0, 19)}</td>
                            <td>${b.reason||'-'}</td>
                            <td><code>${b.method||'ufw'}</code></td>
                            <td><button class="btn btn-secondary" onclick="unblockIp('${b.ip}')">Gỡ chặn</button></td>
                        </tr>`;
                    }
                    tbodyB.innerHTML = hB;
                }

                const resW = await fetch('/api/whitelist');
                const dataW = await resW.json();
                const tbodyW = document.getElementById('tbody-whitelist');
                if (dataW.length === 0) {
                    tbodyW.innerHTML = '<tr><td colspan="5" style="text-align:center; color:#94a3b8;">Danh sách trống</td></tr>';
                } else {
                    let hW = '';
                    for (const w of dataW) {
                        hW += `<tr>
                            <td>#${w.id}</td>
                            <td><strong style="color:var(--accent-green);">${w.ip}</strong></td>
                            <td>${w.note||'-'}</td>
                            <td style="font-size:0.75rem;">${(w.created_at||'').replace('T', ' ').substring(0, 19)}</td>
                            <td><button class="btn btn-danger" onclick="deleteWhitelist('${w.ip}')">Xóa</button></td>
                        </tr>`;
                    }
                    tbodyW.innerHTML = hW;
                }
            } catch (e) {
                console.error(e);
            }
        }

        async function unblockIp(ip) {
            await fetch(`/api/blocked/${ip}/unblock`, { method: 'POST' });
            loadBlockedAndWhitelist();
            fetchStatus();
        }

        async function addWhitelist() {
            const ip = document.getElementById('wl-ip').value.trim();
            const note = document.getElementById('wl-note').value.trim();
            if (!ip) return alert('Vui lòng nhập IP');
            await fetch('/api/whitelist/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, note })
            });
            document.getElementById('wl-ip').value = '';
            document.getElementById('wl-note').value = '';
            loadBlockedAndWhitelist();
        }

        async function deleteWhitelist(ip) {
            await fetch('/api/whitelist/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            });
            loadBlockedAndWhitelist();
        }

        async function loadConfig() {
            const res = await fetch('/api/config');
            const cfg = await res.json();
            document.getElementById('cfg-theta').value = cfg.theta || 0.7;
            document.getElementById('cfg-alpha').value = cfg.alpha || 0.7;
            document.getElementById('cfg-n').value = cfg.window_size_n || 20;
            document.getElementById('cfg-t').value = cfg.window_time_t || 60;
            document.getElementById('cfg-countdown').value = cfg.countdown_seconds || 5;
            document.getElementById('cfg-logpath').value = cfg.log_path || 'data/sample_eve.json';
        }

        async function saveConfig(e) {
            e.preventDefault();
            const payload = {
                theta: parseFloat(document.getElementById('cfg-theta').value),
                alpha: parseFloat(document.getElementById('cfg-alpha').value),
                window_size_n: parseInt(document.getElementById('cfg-n').value),
                window_time_t: parseFloat(document.getElementById('cfg-t').value),
                countdown_seconds: parseInt(document.getElementById('cfg-countdown').value),
                log_path: document.getElementById('cfg-logpath').value.trim()
            };
            const res = await fetch('/api/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            const msgEl = document.getElementById('cfg-save-msg');
            msgEl.innerText = data.message || 'Đã lưu cấu hình!';
            setTimeout(() => { msgEl.innerText = ''; }, 3000);
        }

        window.onload = () => {
            initCharts();
            updateSoundButton();
            fetchStatus();
            fetchAlerts();
            updateCharts();

            setInterval(() => {
                fetchStatus();
                fetchAlerts();
                updateCharts();
            }, 1000);
        };
    </script>
    <!-- Modal hồ sơ bằng chứng cảnh báo -->
    <div id="alert-detail-modal" style="display:none; position:fixed; inset:0; background:rgba(2,6,23,0.85); z-index:9999; align-items:center; justify-content:center; padding:24px;">
        <div style="background:var(--bg-card); border:1px solid var(--border-color); border-radius:10px; width:min(980px, 96vw); max-height:90vh; display:flex; flex-direction:column; box-shadow:0 20px 60px rgba(0,0,0,0.6);">
            <div style="display:flex; align-items:center; justify-content:space-between; padding:16px 20px; border-bottom:1px solid var(--border-color);">
                <h3 style="margin:0; color:var(--accent-blue);">Hồ Sơ Bằng Chứng Cảnh Báo</h3>
                <button class="btn btn-secondary" onclick="closeAlertDetail()">Đóng</button>
            </div>
            <div style="padding:16px 20px; overflow:auto;">
                <pre id="alert-detail-body" style="white-space:pre-wrap; word-break:break-word; font-size:0.8rem; line-height:1.45; margin:0; color:var(--text-main);"></pre>
            </div>
        </div>
    </div>
</body>
</html>
"""


def _session_alert_cutoff(include_history: bool = False) -> str | None:
    """Mốc thời gian lọc cảnh báo hiển thị trên dashboard.

    - Mặc định chỉ trả về cảnh báo phát sinh trong phiên chạy hiện tại
      (``alert.show_only_current_session: true`` trong config.yaml).
    - ``include_history=True`` (nút "Hiện cảnh báo cũ") trả về toàn bộ lịch sử.
    """
    if include_history:
        return None
    cfg = APP_CONTEXT.get("config") or {}
    alert_cfg = cfg.get("alert") or {}
    if not bool(alert_cfg.get("show_only_current_session", True)):
        return None
    return APP_CONTEXT.get("session_started_at")


def _include_history_requested() -> bool:
    return str(request.args.get("include_history", "0")).lower() in ("1", "true", "yes")


def _get_pg_store():
    """Lấy PostgresStore dùng chung; tự khởi tạo khi chỉ chạy riêng dashboard."""
    store = APP_CONTEXT.get("pg_store")
    if store is not None:
        return store
    try:
        from src.pg_store import PostgresStore

        cfg = APP_CONTEXT.get("config") or _load_config_from_file()
        store = PostgresStore(cfg.get("database", {}))
        if store.enabled:
            store.init_schema()
        APP_CONTEXT["pg_store"] = store
        return store
    except Exception as ex:
        logger.warning("Không khởi tạo được PostgresStore cho dashboard: %s", ex)
        return None


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/status", methods=["GET"])
def api_status():
    collector = APP_CONTEXT.get("collector")
    model = APP_CONTEXT.get("model")

    collector_status = "Đang chạy" if (collector and collector.is_alive()) else "Đã dừng / Chờ"
    if model and getattr(model, "is_lstm_loaded", False) and getattr(model, "is_rf_loaded", False):
        model_status = "Ensemble (RF + LSTM)"
    elif model and getattr(model, "is_rf_loaded", False):
        model_status = "Random Forest"
    elif model and getattr(model, "is_loaded", False):
        model_status = "Hoạt động"
    else:
        model_status = "Heuristic (Dự phòng)"

    store = _get_pg_store()
    pipeline = store.get_pipeline_stats() if store is not None else {}
    if pipeline.get("enabled"):
        processed_events = int(pipeline.get("raw_processed", 0))
    else:
        processed_events = collector.processed_events if collector else 0

    stats = get_stats()
    pf = APP_CONTEXT.get("pfsense_collector")
    pf_status = pf.get_status() if pf and hasattr(pf, "get_status") else None

    return jsonify({
        "collector_status": collector_status,
        "model_status": model_status,
        "processed_events": processed_events,
        "blocked_count": stats.get("active_blocked_count", 0),
        "pfsense": pf_status,
        "pipeline": pipeline,
    })


@app.route("/api/pfsense", methods=["GET"])
def api_pfsense():
    pf = APP_CONTEXT.get("pfsense_collector")
    if pf is None:
        return jsonify({"enabled": False, "running": False, "message": "pfSense collector TAT (enabled=false trong config.yaml)"})
    try:
        return jsonify(pf.get_status())
    except Exception as ex:
        return jsonify({"enabled": True, "running": False, "last_error": str(ex)})


@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    include_history = _include_history_requested()
    since = _session_alert_cutoff(include_history)
    alerts = get_alerts(limit=50, since=since)
    alert_mgr = APP_CONTEXT.get("alert_manager")
    countdowns = alert_mgr.get_active_countdowns() if alert_mgr else {}
    return jsonify({
        "alerts": alerts,
        "countdowns": countdowns,
        "session_started_at": APP_CONTEXT.get("session_started_at"),
        "showing_history": include_history,
    })


@app.route("/api/alerts/<int:alert_id>/detail", methods=["GET"])
def api_alert_detail(alert_id: int):
    """Hồ sơ bằng chứng đầy đủ của một cảnh báo (alert + raw event + AI predictions)."""
    alert = get_alert_by_id(alert_id)
    if not alert:
        return jsonify({"success": False, "message": "Không tìm thấy cảnh báo"}), 404

    evidence = alert.get("evidence") or {}
    event_id = evidence.get("event_id") if isinstance(evidence, dict) else None
    raw_event = None
    predictions: list[dict] = []
    store = _get_pg_store()
    if store is not None and event_id:
        raw_event = store.get_event(int(event_id))
        predictions = store.get_predictions_for_event(int(event_id))

    return jsonify({
        "alert": alert,
        "evidence": evidence,
        "raw_event": raw_event,
        "predictions": predictions,
    })


@app.route("/api/alerts/clear", methods=["POST"])
def api_clear_alerts():
    """Xoá toàn bộ cảnh báo trong CSDL (dọn cảnh báo giả/cũ)."""
    try:
        removed = clear_alerts()
    except Exception as ex:
        logger.error("Không xoá được cảnh báo: %s", ex)
        return jsonify({"success": False, "message": f"Lỗi xoá cảnh báo: {ex}"}), 500
    return jsonify({"success": True, "message": f"Đã xoá {removed} cảnh báo"})


@app.route("/api/alerts/<int:alert_id>/block", methods=["POST"])
def api_block_alert(alert_id: int):
    alert_mgr = APP_CONTEXT.get("alert_manager")
    if not alert_mgr:
        return jsonify({"success": False, "message": "AlertManager chưa khởi tạo"}), 500
    success, msg = alert_mgr.manual_block(alert_id)
    return jsonify({"success": success, "message": msg})


@app.route("/api/alerts/<int:alert_id>/ignore", methods=["POST"])
def api_ignore_alert(alert_id: int):
    alert_mgr = APP_CONTEXT.get("alert_manager")
    if not alert_mgr:
        return jsonify({"success": False, "message": "AlertManager chưa khởi tạo"}), 500
    success, msg = alert_mgr.ignore_alert(alert_id)
    return jsonify({"success": success, "message": msg})


@app.route("/api/blocked", methods=["GET"])
def api_get_blocked():
    return jsonify(get_blocked_ips(active_only=True))


@app.route("/api/blocked/<ip>/unblock", methods=["POST"])
def api_unblock_ip(ip: str):
    blocker = APP_CONTEXT.get("blocker")
    if not blocker:
        from src.db import unblock_ip_record
        unblock_ip_record(ip)
        return jsonify({"success": True, "message": f"Đã gỡ chặn IP {ip} trong DB"})
    success, msg = blocker.unblock_ip(ip)
    return jsonify({"success": success, "message": msg})


@app.route("/api/whitelist", methods=["GET"])
def api_get_whitelist():
    return jsonify(get_whitelist())


@app.route("/api/whitelist/add", methods=["POST"])
def api_add_whitelist():
    data = request.get_json() or {}
    ip = data.get("ip", "").strip()
    note = data.get("note", "Thêm qua Dashboard").strip()
    if not ip:
        return jsonify({"success": False, "message": "IP không hợp lệ"}), 400
    ok = add_to_whitelist(ip, note)
    return jsonify({"success": ok, "message": "Đã thêm vào whitelist"})


@app.route("/api/whitelist/delete", methods=["POST"])
def api_delete_whitelist():
    data = request.get_json() or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"success": False, "message": "IP không hợp lệ"}), 400
    ok = remove_from_whitelist(ip)
    return jsonify({"success": ok, "message": "Đã xóa khỏi whitelist"})


@app.route("/api/stats", methods=["GET"])
def api_stats():
    include_history = _include_history_requested()
    since = _session_alert_cutoff(include_history)
    return jsonify(get_stats(since=since))


def _load_config_from_file() -> dict[str, Any]:
    """Đọc tệp cấu hình hiện tại để tránh ghi đè mất các khoá khác."""
    cfg_path = APP_CONTEXT.get("config_path", "config.yaml")
    try:
        with open(cfg_path, "r", encoding="utf-8") as config_file:
            return yaml.safe_load(config_file) or {}
    except Exception as ex:
        logger.warning("Không đọc được tệp cấu hình %s: %s", cfg_path, ex)
        return {}


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    cfg = APP_CONTEXT.get("config") or _load_config_from_file()

    if request.method == "GET":
        scoring_cfg = cfg.get("scoring", {})
        win_cfg = cfg.get("sliding_window", {})
        alert_cfg = cfg.get("alert", {})
        log_cfg = cfg.get("log", {})

        return jsonify({
            "theta": scoring_cfg.get("theta", 0.7),
            "alpha": scoring_cfg.get("alpha", 0.7),
            "window_size_n": win_cfg.get("window_size_n", 20),
            "window_time_t": win_cfg.get("window_time_t", 60),
            "countdown_seconds": alert_cfg.get("countdown_seconds", 5),
            "log_path": log_cfg.get("path", "data/sample_eve.json"),
        })

    data = request.get_json() or {}
    cfg.setdefault("scoring", {})["theta"] = float(data.get("theta", 0.7))
    cfg.setdefault("scoring", {})["alpha"] = float(data.get("alpha", 0.7))
    cfg.setdefault("sliding_window", {})["window_size_n"] = int(data.get("window_size_n", 20))
    cfg.setdefault("sliding_window", {})["window_time_t"] = float(data.get("window_time_t", 60))
    cfg.setdefault("alert", {})["countdown_seconds"] = int(data.get("countdown_seconds", 5))
    cfg.setdefault("log", {})["path"] = str(data.get("log_path", "data/sample_eve.json"))
    APP_CONTEXT["config"] = cfg

    scorer = APP_CONTEXT.get("scorer")
    if scorer:
        scorer.update_parameters(
            alpha=cfg["scoring"]["alpha"],
            theta=cfg["scoring"]["theta"],
        )

    alert_mgr = APP_CONTEXT.get("alert_manager")
    if alert_mgr:
        alert_mgr.countdown_seconds = cfg["alert"]["countdown_seconds"]

    win_tracker = APP_CONTEXT.get("window_tracker")
    if win_tracker:
        win_tracker.window_size_n = cfg["sliding_window"]["window_size_n"]
        win_tracker.window_time_t = cfg["sliding_window"]["window_time_t"]

    cfg_path = APP_CONTEXT.get("config_path", "config.yaml")
    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f, default_flow_style=False, allow_unicode=True)
    except Exception as ex:
        logger.warning("Không thể ghi tệp cấu hình %s: %s", cfg_path, ex)

    return jsonify({"success": True, "message": "Đã lưu và áp dụng cấu hình mới!"})


def run_dashboard(host: str = "0.0.0.0", port: int = 5000, debug: bool = False) -> None:
    logger.info("Khởi động Dashboard tại http://%s:%d", host, port)
    app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    with open("config.yaml", "r", encoding="utf-8") as config_file:
        app_config = yaml.safe_load(config_file) or {}
    init_db(app_config.get("database", {}))
    APP_CONTEXT["config"] = app_config
    APP_CONTEXT["config_path"] = "config.yaml"
    run_dashboard(host="0.0.0.0", port=5000, debug=False)
