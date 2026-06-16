#!/bin/bash
# Script cài đặt WireGuard tự động cho Shield-Core

if [ "$EUID" -ne 0 ]; then
  echo "Vui lòng chạy script bằng quyền root (sudo)"
  exit
fi

echo "======================================"
echo " Shield-Core WireGuard Auto-Installer "
echo "======================================"

# Cài đặt WireGuard
echo "[+] Cài đặt iptables và wireguard..."
apt-get update -y > /dev/null 2>&1
apt-get install -y wireguard iptables > /dev/null 2>&1

# Bật IP Forwarding
echo "[+] Kích hoạt IP Forwarding..."
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-shield-wg.conf
sysctl -p /etc/sysctl.d/99-shield-wg.conf > /dev/null 2>&1

# Tạo thư mục và Key
mkdir -p /etc/wireguard/clients
cd /etc/wireguard
umask 077

if [ ! -f server_private.key ]; then
    echo "[+] Đang tạo khóa bảo mật mới..."
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    wg genkey | tee clients/win_private.key | wg pubkey > clients/win_public.key
fi

SERVER_PRIV=$(cat server_private.key)
SERVER_PUB=$(cat server_public.key)
CLIENT_PRIV=$(cat clients/win_private.key)
CLIENT_PUB=$(cat clients/win_public.key)

# Lấy IP Public
PUBLIC_IP=$(curl -s ifconfig.me)
if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP="ĐỊA_CHỈ_IP_CỦA_VPS_NÀY"
fi

# Tạo Server Config
echo "[+] Khởi tạo cấu hình Server (wg0)..."
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIV

# Bật NAT để gói tin trả về đi đúng đường
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# Windows Backend Client
PublicKey = $CLIENT_PUB
AllowedIPs = 10.8.0.2/32
EOF

# Khởi động WireGuard
echo "[+] Khởi động giao diện mạng wg0..."
systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0

# Tạo Client Config để tải về
cat > /etc/wireguard/clients/windows_backend.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIV
Address = 10.8.0.2/32
DNS = 8.8.8.8

[Peer]
PublicKey = $SERVER_PUB
Endpoint = $PUBLIC_IP:51820
# Để trống AllowedIPs hoặc để 0.0.0.0/0 nếu muốn tất cả đi qua VPN
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

echo "======================================"
echo "✅ HOÀN TẤT CÀI ĐẶT WIREGUARD"
echo "======================================"
echo "Trạng thái wg0:"
wg show
echo ""
echo "======================================"
echo "⚠️ LƯU Ý DÀNH CHO BACKEND WINDOWS ⚠️"
echo "Hãy copy nội dung dưới đây, lưu thành file 'shield.conf' và nạp vào App WireGuard trên máy chủ Windows của bạn:"
echo ""
cat /etc/wireguard/clients/windows_backend.conf
echo "======================================"
