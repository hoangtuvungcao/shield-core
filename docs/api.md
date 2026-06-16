# Tài liệu Đặc tả API (API Specification)

Shield-Core cung cấp giao thức API RESTful bảo mật chạy mặc định trên cổng `9090` thông qua giao thức **HTTPS/TLS**. Giao diện này cho phép quản trị viên tương tác trực tiếp với không gian bộ nhớ eBPF của Kernel để xem số liệu và cấu hình tường lửa.

---

## 1. Cơ chế Xác thực (Authentication)

Mọi truy vấn gửi tới API đều bắt buộc phải kèm theo Header xác thực `X-API-Key`. Khoá API này được tự động sinh ngẫu nhiên ở lần đầu khởi chạy và lưu tại `/opt/shield-core/conf/config.json`.

**Ví dụ Truy vấn bằng curl:**
```bash
curl -k -H "X-API-Key: YOUR_API_KEY" https://localhost:9090/health
```
*(Tham số `-k` / `--insecure` là bắt buộc khi gọi trực tiếp qua địa chỉ IP do sử dụng chứng chỉ SSL tự ký của hệ thống).*

---

## 2. Danh sách Endpoint API

### 2.1. Kiểm tra Sức khỏe Hệ thống (System Health)
* **Endpoint:** `GET /health`
* **Xác thực:** Không yêu cầu (Bypass auth cho giám sát ngoài).
* **Mô tả:** Xem nhanh trạng thái eBPF và thông số tài nguyên hệ thống thực tế.
* **Phản hồi:** `200 OK`
  ```json
  {
    "geoip": {
      "asn": true,
      "country": true
    },
    "status": "healthy",
    "system": {
      "load_1m": 0.14,
      "procs": 204,
      "ram_free": 7369756672,
      "ram_total": 8322023424,
      "ram_used": 487849984
    },
    "uptime_sec": 120,
    "version": "1.0.0",
    "xdp_loaded": true
  }
  ```

---

### 2.2. Quản lý Danh sách đen IP (IP Blacklist)
Đọc, thêm hoặc xoá địa chỉ IP bị chặn ở mức driver mạng card XDP.

#### A. Xem Danh sách IP đang bị chặn
* **Endpoint:** `GET /api/blacklist`
* **Phản hồi:** `200 OK`
  ```json
  ["198.51.100.222", "203.0.113.5"]
  ```

#### B. Chặn IP mới
* **Endpoint:** `POST /api/blacklist`
* **Query Parameters:**
  * `ip` (Bắt buộc): IPv4 hợp lệ cần chặn (ví dụ `1.2.3.4`).
  * `ttl` (Tùy chọn): Thời gian chặn tính bằng giây (Mặc định: `3600`).
* **Phản hồi:** `200 OK`
  ```text
  Đã chặn IP: 1.2.3.4
  ```

#### C. Bỏ chặn IP
* **Endpoint:** `DELETE /api/blacklist`
* **Query Parameters:**
  * `ip` (Bắt buộc): IPv4 cần mở khoá.
* **Phản hồi:** `200 OK`
  ```text
  Đã mở khoá IP: 1.2.3.4
  ```

---

### 2.3. Quản lý Whitelist (IP Whitelist)
Cho phép cấu hình các địa chỉ IP tin cậy đi thẳng qua bộ lọc mạng lên hệ điều hành.

* **Endpoints:**
  * `GET /api/whitelist` $\rightarrow$ Xem danh sách IP tin cậy.
  * `POST /api/whitelist?ip=IP` $\rightarrow$ Thêm IP tin cậy.
  * `DELETE /api/whitelist?ip=IP` $\rightarrow$ Xoá IP tin cậy.

---

### 2.4. Quản lý Chuyển tiếp IPIP (VIP Routing)
Định tuyến lưu lượng sạch từ Shield Node tới các Backend đích.

#### A. Xem Danh sách Routing Map
* **Endpoint:** `GET /api/routing`
* **Phản hồi:** `200 OK`
  ```json
  [
    {
      "vip": "103.77.246.191",
      "backend_ip": "192.168.1.100",
      "type": "IPIP"
    }
  ]
  ```

#### B. Thêm/Cập nhật Map định tuyến
* **Endpoint:** `POST /api/routing`
* **Query Parameters:**
  * `vip` (Bắt buộc): IP VIP nhận lưu lượng trên Shield Node.
  * `backend` (Bắt buộc): IP thật của Backend Server nhận gói tin.
  * `type` (Tùy chọn): Loại đường hầm (`IPIP` hoặc `WireGuard`).
* **Phản hồi:** `200 OK`
  ```text
  Đã map VIP 103.77.246.191 -> Backend 192.168.1.100 (IPIP)
  ```

#### C. Xoá Map định tuyến
* **Endpoint:** `DELETE /api/routing`
* **Query Parameters:**
  * `vip` (Bắt buộc): IP VIP cần xoá.
* **Phản hồi:** `200 OK`
  ```text
  Đã xoá map VIP 103.77.246.191
  ```

---

### 2.5. Xem Thống kê Lưu lượng (Traffic Stats)
* **Endpoint:** `GET /api/stats`
* **Mô tả:** Trả về số lượng gói tin đã đi qua (`XDP_PASS` / `XDP_TX`) và bị huỷ (`XDP_DROP`) thu thập trực tiếp từ eBPF `stats_map`.
* **Phản hồi:** `200 OK`
  ```json
  {
    "passed": 4501239,
    "dropped": 92144
  }
  ```

---

### 2.6. Quản lý Quy tắc Chặn Quốc gia & ASN (GeoIP Rules)
Hỗ trợ chặn diện rộng các dải IP thuộc quốc gia hoặc nhà mạng lớn.

* **Endpoints Chặn ASN:**
  * `GET /api/rules/asn` $\rightarrow$ Xem danh sách CIDR của ASN đang chặn.
  * `POST /api/rules/asn?asn=ASN` $\rightarrow$ Chặn toàn bộ IP thuộc ASN (ví dụ `asn=1234` hoặc `asn=AS1234`).
  * `DELETE /api/rules/asn?asn=ASN` $\rightarrow$ Mở chặn toàn bộ IP thuộc ASN.
* **Endpoints Chặn Quốc gia:**
  * `GET /api/rules/country` $\rightarrow$ Xem danh sách CIDR của các quốc gia đang chặn.
  * `POST /api/rules/country?country=CODE` $\rightarrow$ Chặn toàn bộ IP quốc gia (định dạng ISO-2 ví dụ `country=CN`).
  * `DELETE /api/rules/country?country=CODE` $\rightarrow$ Mở chặn toàn bộ IP quốc gia.

---

### 2.7. Xem Nhật ký Sự kiện Chặn (Mitigation Logs)
* **Endpoint:** `GET /api/logs`
* **Query Parameters:**
  * `limit` (Tùy chọn): Số lượng dòng log tối đa cần lấy (Mặc định: `100`).
* **Phản hồi:** Trả về file text ghi nhận lịch sử các IP bị hệ thống tự động phát hiện chặn.
