# Shield-Core API Reference

Toàn bộ các API đều yêu cầu cung cấp header `X-API-Key` với giá trị khớp với biến `api_key` trong `conf/config.json`.
Cổng mặc định: `9090` (HTTPS).

## 1. Giám Sát (Monitoring)

### Lấy Thống Kê Chung
`GET /api/stats`
- Trả về FSM Level hiện tại, tổng số CPU/RAM, và số packet bị Drop/Pass từ XDP.

### Lấy Prometheus Metrics
`GET /metrics`
- Trả về metrics định dạng chuẩn của Prometheus (không yêu cầu API Key nếu cấu hình open).

### Lấy Mitigation Logs
`GET /api/logs`
- Trả về 100 dòng log phòng thủ gần nhất dưới định dạng JSON array.

## 2. Quản Lý IP (IP Management)

### Quản lý Blacklist
`GET /api/rules/blacklist` - Lấy danh sách IP bị chặn.
`POST /api/rules/blacklist?ip=x.x.x.x` - Thêm IP vào Blacklist.
`DELETE /api/rules/blacklist?ip=x.x.x.x` - Xóa IP khỏi Blacklist.

### Quản lý Whitelist
`GET /api/rules/whitelist` - Lấy danh sách IP ưu tiên.
`POST /api/rules/whitelist?ip=x.x.x.x` - Thêm IP vào Whitelist.
`DELETE /api/rules/whitelist?ip=x.x.x.x` - Xóa IP khỏi Whitelist.

## 3. Quản Lý Địa Lý (GeoIP / ASN)

### Geo Policy
`GET /api/rules/policy` - Lấy chính sách hiện tại (`whitelist` hoặc `blacklist`).
`POST /api/rules/policy?action=whitelist` - Đổi sang mode Whitelist (chặn tất cả trừ danh sách).
`POST /api/rules/policy?action=blacklist` - Đổi sang mode Blacklist (cho phép tất cả trừ danh sách).

### Quản lý Country (Quốc Gia)
`GET /api/rules/country` - Lấy mã các quốc gia đang được áp dụng.
`POST /api/rules/country?code=VN` - Thêm một quốc gia (chuẩn ISO 2 ký tự).
`DELETE /api/rules/country?code=VN` - Xóa một quốc gia.

### Quản lý ASN
`GET /api/rules/asn` - Lấy danh sách ASN.
`POST /api/rules/asn?asn=12345` - Thêm một ASN (nhập số nguyên, không kèm chữ AS).
`DELETE /api/rules/asn?asn=12345` - Xóa ASN.

## 4. Quản Trị Hệ Thống

### Xóa toàn bộ rules (Clear Rules)
`DELETE /api/rules/clear`
- Xóa toàn bộ Whitelist, Blacklist, GeoIP, và ASN khỏi cấu hình.

### Load lại GeoIP Data
`POST /api/system/geoip/reload`
- Tải lại dữ liệu MaxMind `.mmdb` từ ổ cứng không cần khởi động lại.
