# Hướng Dẫn Triển Khai Lên Môi Trường Sản Xuất

Tài liệu này hướng dẫn các bước để biên dịch và triển khai Shield-Core trên các Node Production.

## 1. Yêu Cầu Máy Chủ
- Ubuntu 22.04 LTS hoặc 24.04 LTS.
- GCC/Clang >= 10.
- `make`, `golang` >= 1.22.

## 2. Biên Dịch (Build)
Chạy lệnh tại thư mục gốc:
```bash
make clean
make
```
Hệ thống sẽ biên dịch ra các thành phần sau nằm trong thư mục `build/`:
- `xdp_main.o` (eBPF bytecode)
- `shield-fastpath` (AF_XDP C binary)
- `shield-ctrl` (Control Plane Go binary)

## 3. Cấu hình
Sửa file cấu hình chính:
- Môi trường: `conf/config.json`
- Mạng nội bộ (cụm): `conf/nodes.json`
- GeoIP Database: Tải các file `.mmdb` vào `data/geoip/`.

## 4. Cài đặt Systemd Service
Cài đặt service để quản lý và tự động khởi động cùng hệ thống:
```bash
cp scripts/shield-ctrl.service /etc/systemd/system/
cp scripts/shield-fastpath.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now shield-ctrl shield-fastpath
```

## 5. Cập Nhật Khi Có Phiên Bản Mới (Upgrade)
Để upgrade code mà ít gây gián đoạn nhất:
```bash
make clean && make
systemctl stop shield-ctrl shield-fastpath
cp build/shield-ctrl /opt/shield-core/build/
cp build/shield-fastpath /opt/shield-core/build/
cp src/bpf/xdp_main.o /opt/shield-core/src/bpf/xdp_main.o
systemctl start shield-ctrl
sleep 2
systemctl start shield-fastpath
```
*> Chú ý: Việc restart control plane sẽ tự động reset BPF Maps nên cần thời gian vài giây để hệ thống phục hồi lại trạng thái cấu hình (Persist Load).*
