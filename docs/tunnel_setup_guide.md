# Hướng dẫn Cấu hình Đường Hầm (WireGuard & IPIP) & Định tuyến Cổng Game

Tài liệu này hướng dẫn chi tiết cách cấu hình đường truyền sạch qua **WireGuard** (cho Windows/Linux Backend) và **IPIP Tunnel** (cho Linux Backend) để kết nối cụm 2 Node Shield (Node A & Node B) với máy chủ Backend (BE).

---

## THÔNG TIN KHOÁ WIREGUARD ĐÃ TẠO SẴN TRÊN CÁC NODE VPS

### 1. Node A (103.77.246.191)
- **Public Key**: `WMb6B/mjL4C1V2VfvUjrvmfx0VKtzOfkVtE356444lE=`
- **Private Key**: `6BdoJGyHNznrs7dKrPqF3BW3XisexBxlMZfYT+ueRHw=`
- **Cấu hình trên VPS**: Đã lưu tại `/etc/wireguard/wg0.conf`

### 2. Node B (103.77.246.198)
- **Public Key**: `opZHSpiX9vaZu33U1lp5k0zVlm4VMu92hFiA0NKexUo=`
- **Private Key**: `qB6Fs2Zb1FwQH5QcXtP3tX39umqBOTCWwv9bzi8Zsms=`
- **Cấu hình trên VPS**: Đã lưu tại `/etc/wireguard/wg0.conf`

---

## PHẦN 1: CẤU HÌNH WIREGUARD (Khuyên dùng cho mọi Hệ Điều Hành)

Khi dùng WireGuard, máy chủ game của bạn trên **Windows** hoặc **Linux** sẽ nhận lưu lượng sạch thông qua mạng nội bộ VPN ảo (Dải IP `10.0.0.0/24`).

### Bước 1: Cấu hình trên Windows Server Backend (Máy chủ Game)
1. Tải và cài đặt WireGuard chính thức cho Windows: [Tải WireGuard](https://www.wireguard.com/install/)
2. Mở ứng dụng WireGuard, nhấn mũi tên cạnh nút **Add Tunnel** -> chọn **Add empty tunnel...**
3. Đặt tên đường hầm là `wg0`.
4. Copy toàn bộ nội dung cấu hình sau (hãy tự sinh khóa Private Key cho Backend trên app bằng cách nhấn chọn Generate hoặc app tự tạo):

```ini
[Interface]
PrivateKey = <Khóa_Private_của_Windows_Backend_tự_sinh_trên_app>
Address = 10.0.0.100/24

# Peer 1: Kết nối tới Node A
[Peer]
PublicKey = WMb6B/mjL4C1V2VfvUjrvmfx0VKtzOfkVtE356444lE=
AllowedIPs = 10.0.0.1/32, 103.77.246.191/32
Endpoint = 103.77.246.191:51820
PersistentKeepalive = 25

# Peer 2: Kết nối tới Node B
[Peer]
PublicKey = opZHSpiX9vaZu33U1lp5k0zVlm4VMu92hFiA0NKexUo=
AllowedIPs = 10.0.0.2/32, 103.77.246.198/32
Endpoint = 103.77.246.198:51820
PersistentKeepalive = 25
```
5. Nhấn **Save** và chọn **Activate**.

---

### Bước 2: Cấu hình trên Linux Server Backend (Nếu máy chủ game chạy Linux)
1. Cài đặt WireGuard:
   ```bash
   apt-get update && apt-get install -y wireguard
   ```
2. Tạo file cấu hình `/etc/wireguard/wg0.conf`:
   ```bash
   wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
   ```
3. Đọc private key vừa tạo (`cat /etc/wireguard/privatekey`) và viết cấu hình vào `/etc/wireguard/wg0.conf`:

```ini
[Interface]
PrivateKey = <Điền_Private_Key_vừa_xem>
Address = 10.0.0.100/24
ListenPort = 51820

# Peer 1: Kết nối tới Node A
[Peer]
PublicKey = WMb6B/mjL4C1V2VfvUjrvmfx0VKtzOfkVtE356444lE=
AllowedIPs = 10.0.0.1/32, 103.77.246.191/32
Endpoint = 103.77.246.191:51820
PersistentKeepalive = 25

# Peer 2: Kết nối tới Node B
[Peer]
PublicKey = opZHSpiX9vaZu33U1lp5k0zVlm4VMu92hFiA0NKexUo=
AllowedIPs = 10.0.0.2/32, 103.77.246.198/32
Endpoint = 103.77.246.198:51820
PersistentKeepalive = 25
```
4. Bật đường hầm:
   ```bash
   wg-quick up wg0
   systemctl enable wg-quick@wg0
   ```

---

### Bước 3: Cập nhật config trên Node VPS (A & B) và Kích hoạt định tuyến cổng
1. Để Node A nhận diện Backend, hãy mở file `/etc/wireguard/wg0.conf` trên **Node A** và thêm đoạn sau vào cuối:
   ```ini
   [Peer]
   PublicKey = <Điền_Public_Key_của_Backend>
   AllowedIPs = 10.0.0.100/32
   Endpoint = <IP_WAN_của_Backend>:51820
   PersistentKeepalive = 25
   ```
   Chạy lệnh: `wg-quick down wg0 && wg-quick up wg0`
2. Làm tương tự trên **Node B**.
3. **Kích hoạt định tuyến cổng game qua API**:
   Dùng lệnh `curl` từ bất kỳ đâu gửi đến một trong các node (hệ thống sẽ tự động đồng bộ NAT sang node kia):
   ```bash
   # Map cổng game TCP 25565 của VIP về cổng 25565 của Backend qua WireGuard (10.0.0.100)
   curl -k -X POST -H "X-API-Key: 14f0031a85e3a4f9ee7e6b374831b3b71ac8797f0d92a6f70f22a006dad1639d" \
     "https://103.77.246.198:9090/api/routing?vip=103.77.246.198&vport=25565&protocol=tcp&backend=10.0.0.100:25565&type=wireguard"
   ```

---

## PHẦN 2: CẤU HÌNH ĐƯỜNG HẦM IPIP (Chỉ dành cho Linux Backend)

Đường hầm IPIP giúp eBPF xử lý trực tiếp tại XDP driver với hiệu năng cực cao mà không cần mã hóa VPN.

### Bước 1: Thiết lập trên Linux Backend
Chạy script dưới đây trên máy chủ Backend của bạn để tạo 2 đường hầm kết nối với Node A và Node B:

```bash
#!/bin/bash
# 1. Nạp module IPIP
modprobe ipip

# 2. Đường hầm tới Node A (Dải IP tunnel: 10.1.0.0/24)
ip tunnel add ipip-nodea mode ipip local <IP_WAN_Backend> remote 103.77.246.191
ip addr add 10.1.0.100/24 dev ipip-nodea
ip link set ipip-nodea up

# 3. Đường hầm tới Node B (Dải IP tunnel: 10.2.0.0/24)
ip tunnel add ipip-nodeb mode ipip local <IP_WAN_Backend> remote 103.77.246.198
ip addr add 10.2.0.100/24 dev ipip-nodeb
ip link set ipip-nodeb up

# 4. Gán VIP IP lên card loopback để nhận gói tin
ip addr add 103.77.246.191/32 dev lo
ip addr add 103.77.246.198/32 dev lo

# 5. Thiết lập Policy Routing để phản hồi quay lại đúng Node gửi
ip rule add from 103.77.246.191 table 100
ip route add default dev ipip-nodea table 100

ip rule add from 103.77.246.198 table 200
ip route add default dev ipip-nodeb table 200

echo "Cấu hình IPIP Tunnel hoàn tất!"
```

### Bước 2: Kích hoạt định tuyến cổng trên cụm Shield
Bắn API cấu hình định tuyến thông qua cổng game sử dụng giao thức IPIP:
- **Ánh xạ qua Node A**:
  ```bash
  curl -k -X POST -H "X-API-Key: 14f0031a85e3a4f9ee7e6b374831b3b71ac8797f0d92a6f70f22a006dad1639d" \
    "https://103.77.246.198:9090/api/routing?vip=103.77.246.191&vport=25565&protocol=tcp&backend=10.1.0.100:25565&type=ipip"
  ```
- **Ánh xạ qua Node B**:
  ```bash
  curl -k -X POST -H "X-API-Key: 14f0031a85e3a4f9ee7e6b374831b3b71ac8797f0d92a6f70f22a006dad1639d" \
    "https://103.77.246.198:9090/api/routing?vip=103.77.246.198&vport=25565&protocol=tcp&backend=10.2.0.100:25565&type=ipip"
  ```
