#!/bin/bash
set -euo pipefail

# =====================================================
# Shield-Core Production Install Script
# =====================================================

INSTALL_DIR="/opt/shield-core"
SERVICE_USER="root"
SYSTEMD_DIR="/etc/systemd/system"

echo "============================================"
echo " Shield-Core Anti-DDoS Platform - Installer"
echo "============================================"

# Kiểm tra quyền root
if [ "$(id -u)" -ne 0 ]; then
    echo "Lỗi: Script này cần chạy với quyền root (sudo)."
    exit 1
fi

# Kiểm tra kernel version (cần ≥ 5.8 cho bpf_tcp_gen_syncookie)
KVER=$(uname -r | cut -d. -f1-2)
MAJOR=$(echo "$KVER" | cut -d. -f1)
MINOR=$(echo "$KVER" | cut -d. -f2)
if [ "$MAJOR" -lt 5 ] || { [ "$MAJOR" -eq 5 ] && [ "$MINOR" -lt 8 ]; }; then
    echo "Cảnh báo: Kernel $KVER < 5.8. SYN Cookie trong XDP sẽ không hoạt động."
    echo "Khuyến nghị sử dụng Kernel 5.15+ hoặc 6.x."
fi

# Tạo thư mục cài đặt
echo "[1/6] Tạo thư mục cài đặt tại ${INSTALL_DIR}..."
mkdir -p ${INSTALL_DIR}/{build,conf,data/geoip,logs,src/bpf}

# Copy binaries
echo "[2/6] Copy binaries..."
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cp -v "${SCRIPT_DIR}/build/shield-ctrl" "${INSTALL_DIR}/build/" 2>/dev/null || echo "  -> shield-ctrl chưa build. Chạy 'make' trước."
cp -v "${SCRIPT_DIR}/build/shield-fastpath" "${INSTALL_DIR}/build/" 2>/dev/null || echo "  -> shield-fastpath chưa build."
cp -v "${SCRIPT_DIR}/src/bpf/xdp_main.o" "${INSTALL_DIR}/src/bpf/" 2>/dev/null || echo "  -> xdp_main.o chưa compile."

# Copy configs
echo "[3/6] Copy cấu hình..."
cp -n "${SCRIPT_DIR}/conf/config.json" "${INSTALL_DIR}/conf/" 2>/dev/null || true
cp -n "${SCRIPT_DIR}/conf/reputation.json" "${INSTALL_DIR}/conf/" 2>/dev/null || true
cp -n "${SCRIPT_DIR}/conf/nodes.json" "${INSTALL_DIR}/conf/" 2>/dev/null || true

# Copy GeoIP data
echo "[4/6] Copy GeoIP database..."
if [ -d "${SCRIPT_DIR}/data/geoip" ]; then
    cp -v "${SCRIPT_DIR}"/data/geoip/*.mmdb "${INSTALL_DIR}/data/geoip/" 2>/dev/null || echo "  -> Chưa có file MMDB."
else
    echo "  -> Thư mục data/geoip không tồn tại. Tải MaxMind GeoLite2 database."
fi

# Cài đặt systemd services
echo "[5/6] Cài đặt systemd services..."
cp -v "${SCRIPT_DIR}/scripts/shield-ctrl.service" "${SYSTEMD_DIR}/"
cp -v "${SCRIPT_DIR}/scripts/shield-fastpath.service" "${SYSTEMD_DIR}/"
systemctl daemon-reload

# Set permissions
echo "[6/7] Thiết lập quyền..."
chmod +x ${INSTALL_DIR}/build/* 2>/dev/null || true
chmod 600 ${INSTALL_DIR}/conf/config.json 2>/dev/null || true
mkdir -p /sys/fs/bpf/shield_core
chown -R nobody:nogroup ${INSTALL_DIR}
chown -R nobody:nogroup /sys/fs/bpf/shield_core

# Logrotate
echo "[7/7] Cài đặt logrotate..."
if [ -f "${SCRIPT_DIR}/scripts/shield-core.logrotate" ]; then
    cp -v "${SCRIPT_DIR}/scripts/shield-core.logrotate" /etc/logrotate.d/shield-core
    echo "  -> Log rotation được kích hoạt (30 ngày, max 100MB/file)"
fi

echo ""
echo "============================================"
echo " Cài đặt hoàn tất!"
echo "============================================"
echo ""
echo "Các bước tiếp theo:"
echo "  1. Chỉnh sửa: ${INSTALL_DIR}/conf/config.json"
echo "     - Đặt api_key cố định cho production"
echo "     - Kiểm tra đường dẫn GeoIP database"
echo ""
echo "  2. Đặt interface mạng trong systemd:"
echo "     vi ${SYSTEMD_DIR}/shield-ctrl.service"
echo "     -> Environment=SHIELD_IFACE=eth0"
echo ""
echo "  3. Khởi động:"
echo "     systemctl enable --now shield-ctrl"
echo "     systemctl enable --now shield-fastpath"
echo ""
echo "  4. Kiểm tra:"
echo "     systemctl status shield-ctrl"
echo "     curl -k https://localhost:9090/health"
echo "     curl -k https://localhost:9090/metrics"
echo ""
