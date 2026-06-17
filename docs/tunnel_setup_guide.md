# Hướng dẫn Cấu hình Đường Hầm (WireGuard & IPIP) & Định tuyến Cổng Game (Tự Động)

Hệ thống đã được **tự động hóa hoàn toàn** việc cấu hình WireGuard trên các Node VPS khi bạn gọi API định tuyến. Bạn không cần phải SSH vào các Node VPS để sửa file cấu hình nữa!

---

## THÔNG TIN KHOÁ WIREGUARD CỦA CỤM VPS
Bạn cần lưu lại các khóa Public Key này để cấu hình trên Backend của mình:

- **Public Key của Node A (103.77.246.191)**: `WMb6B/mjL4C1V2VfvUjrvmfx0VKtzOfkVtE356444lE=`
- **Public Key của Node B (103.77.246.198)**: `opZHSpiX9vaZu33U1lp5k0zVlm4VMu92hFiA0NKexUo=`

---

## BƯỚC 1: Cấu hình trên máy chủ Backend của bạn (Windows/Linux)

Bạn chỉ cần cấu hình duy nhất một lần trên máy chủ Backend của mình để kết nối VPN tới 2 Node.

### A. Nếu Backend là Windows Server
1. Tải và cài đặt: [WireGuard Windows](https://www.wireguard.com/install/)
2. Tạo Tunnel mới đặt tên là `wg0` với nội dung cấu hình sau:
```ini
[Interface]
PrivateKey = <Private_Key_của_Windows_Backend_tự_sinh_trên_app>
Address = 10.0.0.100/24

# Kết nối tới Node A
[Peer]
PublicKey = WMb6B/mjL4C1V2VfvUjrvmfx0VKtzOfkVtE356444lE=
AllowedIPs = 10.0.0.1/32, 103.77.246.191/32
Endpoint = 103.77.246.191:51820
PersistentKeepalive = 25

# Kết nối tới Node B
[Peer]
PublicKey = opZHSpiX9vaZu33U1lp5k0zVlm4VMu92hFiA0NKexUo=
AllowedIPs = 10.0.0.2/32, 103.77.246.198/32
Endpoint = 103.77.246.198:51820
PersistentKeepalive = 25
```
3. Nhấn **Save** và chọn **Activate**.

### B. Nếu Backend là Linux Server
Tạo file `/etc/wireguard/wg0.conf` trên Linux Backend với nội dung tương tự (sử dụng private key tự sinh):
```ini
[Interface]
PrivateKey = <Private_Key_của_Linux_Backend>
Address = 10.0.0.100/24
ListenPort = 51820

# Kết nối tới Node A
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
Chạy lệnh kích hoạt: `wg-quick up wg0 && systemctl enable wg-quick@wg0`.

---

## BƯỚC 2: Gọi API định tuyến để hệ thống tự kết nối

Khi đã có Public Key của Backend (ví dụ: `myBackendPublicKey...`), bạn chỉ cần gọi duy nhất một lệnh API `curl` đến một node bất kỳ. Hệ thống sẽ tự động cấu hình nóng WireGuard Peer trên cả Node A và Node B đồng loạt:

### Lệnh thêm định tuyến cổng game (25565):
```bash
curl -k -X POST -H "X-API-Key: 14f0031a85e3a4f9ee7e6b374831b3b71ac8797f0d92a6f70f22a006dad1639d" \
  "https://103.77.246.198:9090/api/routing?vip=103.77.246.198&vport=25565&protocol=tcp&backend=10.0.0.100:25565&type=wireguard&pubkey=<Public_Key_của_Backend>&endpoint=<IP_WAN_Backend>:51820"
```
*(Hệ thống sẽ tự động thêm cấu hình Peer trên cả hai VPS Node, nạp định tuyến vào eBPF map và NAT port qua iptables tương ứng).*

### Lệnh xóa định tuyến:
```bash
curl -k -X DELETE -H "X-API-Key: 14f0031a85e3a4f9ee7e6b374831b3b71ac8797f0d92a6f70f22a006dad1639d" \
  "https://103.77.246.198:9090/api/routing?vip=103.77.246.198&vport=25565&protocol=tcp&backend=10.0.0.100:25565&type=wireguard&pubkey=<Public_Key_của_Backend>"
```
*(Hệ thống sẽ gỡ bỏ cài đặt Peer trên cả hai VPS Node và xóa quy tắc NAT tương ứng).*

---

## PHẦN 3: ĐỐI VỚI IPIP TUNNEL (Chỉ hỗ trợ Linux Backend)

Chạy script dưới đây trên máy chủ Linux Backend của bạn để tự động kết nối:
```bash
#!/bin/bash
modprobe ipip

# Kết nối Node A
ip tunnel add ipip-nodea mode ipip local <IP_WAN_Backend> remote 103.77.246.191
ip addr add 10.1.0.100/24 dev ipip-nodea
ip link set ipip-nodea up

# Kết nối Node B
ip tunnel add ipip-nodeb mode ipip local <IP_WAN_Backend> remote 103.77.246.198
ip addr add 10.2.0.100/24 dev ipip-nodeb
ip link set ipip-nodeb up

# Nhận diện VIP IP
ip addr add 103.77.246.191/32 dev lo
ip addr add 103.77.246.198/32 dev lo

# Định tuyến phản hồi
ip rule add from 103.77.246.191 table 100
ip route add default dev ipip-nodea table 100

ip rule add from 103.77.246.198 table 200
ip route add default dev ipip-nodeb table 200
```
Sau đó bắn API loại `type=ipip` (không cần tham số `pubkey` và `endpoint` vì IPIP không mã hóa):
```bash
curl -k -X POST -H "X-API-Key: 14f0031a85e3a4f9ee7e6b374831b3b71ac8797f0d92a6f70f22a006dad1639d" \
  "https://103.77.246.198:9090/api/routing?vip=103.77.246.198&vport=25565&protocol=tcp&backend=10.2.0.100:25565&type=ipip"
```
