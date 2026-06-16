package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

type GeoIPManager struct {
	mu             sync.RWMutex
	asnReader      *maxminddb.Reader
	countryReader  *maxminddb.Reader
	asnLoaded      bool
	countryLoaded  bool
	lastReloadTime time.Time
	asnPath        string
	countryPath    string
	asnSize        int64
	countrySize    int64
	asnVersion     string
	countryVersion string

	// Thread-Safe Caching
	asnCache       map[uint32][]string
	countryCache   map[string][]string
	cacheHits      uint64
	cacheMisses    uint64
}

var geoIPMgr *GeoIPManager

func InitGeoIPManager(asnPath, countryPath string) *GeoIPManager {
	mgr := &GeoIPManager{
		asnPath:     asnPath,
		countryPath: countryPath,
	}
	mgr.Reload()
	return mgr
}

func resolvePath(path string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}
	altPath := "../" + path
	if _, err := os.Stat(altPath); err == nil {
		return altPath
	}
	return path
}

func (g *GeoIPManager) Reload() {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.lastReloadTime = time.Now()

	// Xóa/khởi tạo lại cache khi reload nóng
	g.asnCache = make(map[uint32][]string)
	g.countryCache = make(map[string][]string)
	g.cacheHits = 0
	g.cacheMisses = 0

	resolvedASN := resolvePath(g.asnPath)
	resolvedCountry := resolvePath(g.countryPath)

	// Đọc ASN DB
	if stat, err := os.Stat(resolvedASN); err == nil {
		if reader, err := maxminddb.Open(resolvedASN); err == nil {
			// Validation: Đảm bảo đúng loại file database
			dbType := strings.ToLower(reader.Metadata.DatabaseType)
			if strings.Contains(dbType, "asn") || strings.Contains(dbType, "isp") {
				if g.asnReader != nil {
					g.asnReader.Close()
				}
				g.asnReader = reader
				g.asnLoaded = true
				g.asnSize = stat.Size()
				g.asnVersion = fmt.Sprintf("%d.%d", reader.Metadata.BinaryFormatMajorVersion, reader.Metadata.BinaryFormatMinorVersion)
				log.Printf("[GeoIP] Nạp thành công ASN Database: %s (Type: %s)", resolvedASN, reader.Metadata.DatabaseType)
			} else {
				log.Printf("[GeoIP] Lỗi xác thực: File %s không phải là ASN Database (Kiểu thực tế: %s). Bỏ qua nạp.", resolvedASN, reader.Metadata.DatabaseType)
				reader.Close()
			}
		} else {
			log.Printf("[GeoIP] Cảnh báo: Lỗi mở ASN DB %s: %v (Giữ nguyên database cũ nếu có)", resolvedASN, err)
		}
	} else {
		log.Printf("[GeoIP] Cảnh báo: Thiếu file ASN DB %s (Chạy chế độ degraded cho ASN)", g.asnPath)
	}

	// Đọc Country DB
	if stat, err := os.Stat(resolvedCountry); err == nil {
		if reader, err := maxminddb.Open(resolvedCountry); err == nil {
			// Validation: Đảm bảo đúng loại file database
			dbType := strings.ToLower(reader.Metadata.DatabaseType)
			if strings.Contains(dbType, "country") || strings.Contains(dbType, "city") {
				if g.countryReader != nil {
					g.countryReader.Close()
				}
				g.countryReader = reader
				g.countryLoaded = true
				g.countrySize = stat.Size()
				g.countryVersion = fmt.Sprintf("%d.%d", reader.Metadata.BinaryFormatMajorVersion, reader.Metadata.BinaryFormatMinorVersion)
				log.Printf("[GeoIP] Nạp thành công Country Database: %s (Type: %s)", resolvedCountry, reader.Metadata.DatabaseType)
			} else {
				log.Printf("[GeoIP] Lỗi xác thực: File %s không phải là Country Database (Kiểu thực tế: %s). Bỏ qua nạp.", resolvedCountry, reader.Metadata.DatabaseType)
				reader.Close()
			}
		} else {
			log.Printf("[GeoIP] Cảnh báo: Lỗi mở Country DB %s: %v (Giữ nguyên database cũ nếu có)", resolvedCountry, err)
		}
	} else {
		log.Printf("[GeoIP] Cảnh báo: Thiếu file Country DB %s (Chạy chế độ degraded cho Country)", g.countryPath)
	}
}

func (g *GeoIPManager) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.asnReader != nil {
		g.asnReader.Close()
		g.asnReader = nil
	}
	if g.countryReader != nil {
		g.countryReader.Close()
		g.countryReader = nil
	}
}

// BlockCountry CIDRs bằng cách duyệt qua Database và lấy tất cả subnets của country đó
func (g *GeoIPManager) GetCountryCIDRs(countryCode string) ([]string, error) {
	g.mu.RLock()
	if g.countryCache != nil {
		if cidrs, ok := g.countryCache[countryCode]; ok {
			atomic.AddUint64(&g.cacheHits, 1)
			g.mu.RUnlock()
			return cidrs, nil
		}
	}

	if !g.countryLoaded || g.countryReader == nil {
		g.mu.RUnlock()
		return nil, fmt.Errorf("Country database chưa được nạp (Degraded Mode)")
	}
	g.mu.RUnlock()

	g.mu.Lock()
	defer g.mu.Unlock()

	// Kiểm tra lại lần nữa trong trường hợp race condition
	if g.countryCache == nil {
		g.countryCache = make(map[string][]string)
	}
	if cidrs, ok := g.countryCache[countryCode]; ok {
		atomic.AddUint64(&g.cacheHits, 1)
		return cidrs, nil
	}

	atomic.AddUint64(&g.cacheMisses, 1)
	var cidrs []string
	networks := g.countryReader.Networks(maxminddb.SkipAliasedNetworks)
	
	type CountryRec struct {
		Country struct {
			IsoCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}

	var record CountryRec
	for networks.Next() {
		subnet, err := networks.Network(&record)
		if err != nil {
			continue
		}
		if record.Country.IsoCode == countryCode {
			cidrs = append(cidrs, subnet.String())
		}
	}

	g.countryCache[countryCode] = cidrs
	return cidrs, nil
}

// BlockASN CIDRs bằng cách duyệt qua ASN Database và lấy tất cả subnets của ASN đó
func (g *GeoIPManager) GetASNCIDRs(targetASN uint32) ([]string, error) {
	g.mu.RLock()
	if g.asnCache != nil {
		if cidrs, ok := g.asnCache[targetASN]; ok {
			atomic.AddUint64(&g.cacheHits, 1)
			g.mu.RUnlock()
			return cidrs, nil
		}
	}

	if !g.asnLoaded || g.asnReader == nil {
		g.mu.RUnlock()
		return nil, fmt.Errorf("ASN database chưa được nạp (Degraded Mode)")
	}
	g.mu.RUnlock()

	g.mu.Lock()
	defer g.mu.Unlock()

	// Kiểm tra lại lần nữa trong trường hợp race condition
	if g.asnCache == nil {
		g.asnCache = make(map[uint32][]string)
	}
	if cidrs, ok := g.asnCache[targetASN]; ok {
		atomic.AddUint64(&g.cacheHits, 1)
		return cidrs, nil
	}

	atomic.AddUint64(&g.cacheMisses, 1)
	var cidrs []string
	networks := g.asnReader.Networks(maxminddb.SkipAliasedNetworks)

	type ASNRec struct {
		AutonomousSystemNumber uint32 `maxminddb:"autonomous_system_number"`
	}

	var record ASNRec
	for networks.Next() {
		subnet, err := networks.Network(&record)
		if err != nil {
			continue
		}
		if record.AutonomousSystemNumber == targetASN {
			cidrs = append(cidrs, subnet.String())
		}
	}

	g.asnCache[targetASN] = cidrs
	return cidrs, nil
}
