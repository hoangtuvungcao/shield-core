# Cơ chế Định vị Địa lý & ASN (GeoIP & ASN Filtering)

Shield-Core tích hợp cơ chế lọc gói tin theo Quốc gia (GeoIP) và Tổ chức quản lý mạng (ASN) ở cấp độ eBPF Kernel bằng cách kết hợp thư viện đọc database MaxMind ở User space và cấu trúc dữ liệu tìm kiếm tiền tố dài nhất (LPM Trie) trong nhân Kernel.

---

## 1. Nguyên lý Hoạt động

Do việc nạp và phân tích trực tiếp file cơ sở dữ liệu MaxMind (.mmdb) khổng lồ trong nhân eBPF là không khả thi (vì giới hạn bộ nhớ verifier và kích thước file), Shield-Core giải quyết bằng cơ chế hỗn hợp:

1. **User space (Go):** Đọc cơ sở dữ liệu `GeoLite2-Country.mmdb` và `GeoLite2-ASN.mmdb` từ MaxMind thông qua kịch bản `geoip.go`.
2. **eBPF Kernel:** Khai báo hai bản đồ kiểu LPM Trie (`lpm_trie`):
   * `asn_blacklist_map` (max_entries: 65,536)
   * `country_blacklist_map` (max_entries: 65,536)
3. **Ánh xạ IP thành Tiền tố:** Khi quản trị viên yêu cầu chặn một Quốc gia (ví dụ: `CN` - Trung Quốc) hoặc một ASN (ví dụ: `AS1234`), Go Control Plane sẽ duyệt cơ sở dữ liệu để tìm toàn bộ các dải mạng (subnets) tương ứng và nạp trực tiếp chúng vào LPM Trie map của eBPF.
4. **Lọc siêu tốc:** Khi gói tin đi vào card mạng, eBPF XDP thực hiện tra cứu địa chỉ IP nguồn (`iph->saddr`) đối chiếu với LPM Trie map. Nếu tìm thấy tiền tố mạng trùng khớp, gói tin bị huỷ bỏ (`XDP_DROP`) ngay lập tức mà không cần đi qua CPU ứng dụng.

---

## 2. Quản lý Bộ nhớ đệm (Thread-Safe Caching)

Việc duyệt toàn bộ các subnet của một quốc gia lớn trong file MMDB có thể mất từ 0.5 - 1.5 giây tùy thuộc vào CPU máy chủ. Để tối ưu hóa tài nguyên mạng và thời gian phản hồi API, Go Control Plane tích hợp bộ đệm an toàn đa luồng (Thread-Safe Cache):

* **Cấu trúc bộ đệm:**
  * `asnCache map[uint32][]string`: Lưu danh sách các CIDR đã phân giải của ASN.
  * `countryCache map[string][]string`: Lưu danh sách các CIDR đã phân giải của Quốc gia.
* **Cơ chế đồng bộ:** Sử dụng khóa đọc ghi `sync.RWMutex` kết hợp đếm nguyên tử `sync/atomic` cho các chỉ số `cacheHits` và `cacheMisses` phục vụ xuất dữ liệu Prometheus Metrics.
* Khi reload nóng database hoặc cấu hình, cache sẽ tự động được xoá sạch để nạp thông tin mới nhất.

---

## 3. Quản lý cấu hình & Cập nhật Nóng (Hot Reload)

### 3.1. Reload Cập nhật DB
Khi cập nhật phiên bản mới của các file database MaxMind trong thư mục `data/geoip/`, quản trị viên không cần phải khởi động lại dịch vụ Shield-Core. Bạn chỉ cần gọi API reload nóng:
```bash
curl -k -X POST -H "X-API-Key: YOUR_API_KEY" https://localhost:9090/api/geoip/reload
```
Hệ thống sẽ thực hiện:
1. Đóng các file reader cũ an toàn.
2. Kiểm tra tính hợp lệ của database mới (đảm bảo đúng cấu trúc ASN / Country database).
3. Đọc dữ liệu mới và xoá bộ đệm cache cũ.

### 3.2. Kiểm tra Sức khỏe GeoIP
Quản trị viên có thể xem thông tin chi tiết về kích thước file, phiên bản và tình trạng nạp của database qua endpoint:
```bash
curl -k -H "X-API-Key: YOUR_API_KEY" https://localhost:9090/api/geoip/health
```
**Phản hồi ví dụ:**
```json
{
  "asn_loaded": true,
  "country_loaded": true,
  "asn_db_size": 7654321,
  "country_db_size": 4321098,
  "asn_version": "2.0",
  "country_version": "2.0",
  "last_reload": "2026-06-16T16:19:34+07:00",
  "cache_hits": 124,
  "cache_misses": 2
}
```
---

## 4. Định dạng Quy tắc trong API

* **Chặn ASN:** `POST /api/rules/asn?asn=1234` hoặc `DELETE /api/rules/asn?asn=1234`
* **Chặn Quốc gia:** `POST /api/rules/country?country=CN` hoặc `DELETE /api/rules/country?country=CN`
*(Mã quốc gia sử dụng định dạng ISO-2 chữ in hoa, ví dụ: CN, US, RU, BR).*
