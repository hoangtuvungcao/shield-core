package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func generateSelfSignedCert(certPath, keyPath string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Shield-Core"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && !ipNet.IP.IsLoopback() {
				template.IPAddresses = append(template.IPAddresses, ipNet.IP)
			}
		}
	}
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}

	return nil
}

func ensureCertificatesExist(certPath, keyPath string) {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return
		}
	}
	log.Printf("[Security] Không tìm thấy chứng chỉ SSL, đang tự động tạo chứng chỉ SSL tự ký tại %s và %s...", certPath, keyPath)
	if err := generateSelfSignedCert(certPath, keyPath); err != nil {
		log.Fatalf("[Security] Lỗi nghiêm trọng: Không thể tạo chứng chỉ SSL tự ký: %v", err)
	}
	log.Println("[Security] Đã tạo thành công chứng chỉ SSL tự ký.")
}

var mapMgr *MapManager
var configuredAPIKey string
var listenAddr string

func main() {
	log.Println("Đang khởi động Shield-Core Control Plane...")

	// Gỡ bỏ giới hạn MEMLOCK (bắt buộc đối với eBPF)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[CẢNH BÁO] Không thể gỡ bỏ giới hạn MEMLOCK: %v", err)
	}

	// Nạp cấu hình config.json
	cfgPath := resolvePath("conf/config.json")
	config, err := LoadConfig(cfgPath)
	if err != nil {
		log.Printf("[CẤU HÌNH] Cảnh báo: Không thể tải config.json từ %s: %v. Sử dụng cấu hình mặc định cho GeoIP.", cfgPath, err)
		config.GeoIP.AsnDBPath = "data/geoip/GeoLite2-ASN.mmdb"
		config.GeoIP.CountryDBPath = "data/geoip/GeoLite2-Country.mmdb"
	}
	listenAddr = config.API.Listen

	// Đảm bảo chứng chỉ SSL tồn tại
	certPath := resolvePath("conf/cert.pem")
	keyPath := resolvePath("conf/key.pem")
	os.MkdirAll(filepath.Dir(certPath), 0755)
	ensureCertificatesExist(certPath, keyPath)

	// Khởi tạo GeoIPManager (Hỗ trợ Degraded Mode)
	geoIPMgr = InitGeoIPManager(config.GeoIP.AsnDBPath, config.GeoIP.CountryDBPath)
	defer geoIPMgr.Close()

	// Interface cần bảo vệ — đặt qua biến môi trường SHIELD_IFACE
	iface := os.Getenv("SHIELD_IFACE")
	if iface == "" {
		iface = "eth0" // Mặc định: interface chính
		log.Printf("[CONFIG] SHIELD_IFACE chưa được đặt, sử dụng mặc định: %s", iface)
	}

	// Đường dẫn tới file ELF (sẽ được compile ở thư mục bpf)
	objPath := resolvePath("src/bpf/xdp_main.o")

	// Load BPF Program
	prog, err := LoadXDPProgram(iface, objPath)
	if err != nil {
		// [Degraded Mode] XDP program chưa compile hoặc NIC không hỗ trợ.
		// Control Plane vẫn khởi động với API + GeoIP nhưng không có datapath filtering.
		log.Printf("[CẢNH BÁO] Không thể load XDP program: %v", err)
		log.Printf("Vui lòng compile eBPF C code ra %s trước khi chạy thực tế.", objPath)
	} else {
		defer prog.Close()
		mapMgr = NewMapManager(prog)
		log.Println("XDP Datapath đã sẵn sàng.")

		// Khởi tạo config_map cho rate limits
		if err := mapMgr.UpdateRateLimits(5000, 10*1024*1024); err != nil {
			log.Printf("[CẤU HÌNH] Lỗi khởi tạo config_map cho rate limits: %v", err)
		} else {
			log.Println("[CẤU HÌNH] Đã khởi tạo config_map cho rate limits (5000 PPS, 10MB/s).")
		}

		// Nạp cơ sở dữ liệu Reputation
		loadReputationDatabase(resolvePath("conf/reputation.json"))

		// Nạp danh sách cluster nodes để đồng bộ
		loadClusterNodes(resolvePath("conf/nodes.json"))

		// Khởi tạo persistence và khôi phục state từ lần chạy trước
		initPersistence()
		restoreRulesState()

		// Khởi chạy Auto-Mitigation Engine chạy ngầm
		go startAutoMitigation()

		// Khởi chạy đồng bộ danh sách cổng mạng nội bộ đang chạy để XDP tự động bypass
	}

	// API Authentication Middleware
	apiKey := config.API.Key
	configuredAPIKey = apiKey
	authMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Cho phép sync requests từ cluster nodes khác dùng query param
			if r.URL.Query().Get("sync") == "true" {
				syncKey := r.Header.Get("X-API-Key")
				if syncKey != apiKey {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			} else {
				key := r.Header.Get("X-API-Key")
				if key != apiKey {
					http.Error(w, "Unauthorized: Thiếu hoặc sai API Key (Header: X-API-Key)", http.StatusUnauthorized)
					return
				}
			}
			next(w, r)
		}
	}

	// API Rate Limiter (per-IP, 60 requests/phút)
	type rateLimitEntry struct {
		count   int
		resetAt time.Time
	}
	var rateLimitMap sync.Map
	rateLimitMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			clientIP := r.RemoteAddr
			now := time.Now()
			val, _ := rateLimitMap.LoadOrStore(clientIP, &rateLimitEntry{count: 0, resetAt: now.Add(time.Minute)})
			entry := val.(*rateLimitEntry)
			if now.After(entry.resetAt) {
				entry.count = 0
				entry.resetAt = now.Add(time.Minute)
			}
			entry.count++
			if entry.count > 60 {
				http.Error(w, "Rate limit exceeded (60 req/min)", http.StatusTooManyRequests)
				return
			}
			next(w, r)
		}
	}

	// Khởi tạo API Server (các endpoint quản trị yêu cầu xác thực + rate limit)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/blacklist", rateLimitMiddleware(authMiddleware(handleBlacklist)))
	mux.HandleFunc("/api/routing", rateLimitMiddleware(authMiddleware(handleRouting)))
	mux.HandleFunc("/api/stats", rateLimitMiddleware(authMiddleware(handleStats)))

	mux.HandleFunc("/api/geoip/health", rateLimitMiddleware(authMiddleware(handleGeoIPHealth)))
	mux.HandleFunc("/api/geoip/reload", rateLimitMiddleware(authMiddleware(handleGeoIPReload)))
	mux.HandleFunc("/api/whitelist", rateLimitMiddleware(authMiddleware(handleWhitelist)))
	mux.HandleFunc("/api/rules/policy", rateLimitMiddleware(authMiddleware(handleRulesPolicy)))
	mux.HandleFunc("/api/logs", rateLimitMiddleware(authMiddleware(handleLogs)))
	// Prometheus metrics endpoint (public - chuẩn cho scraping)
	mux.HandleFunc("/metrics", handlePrometheusMetrics)
	// Health Check endpoint (public - chuẩn cho Load Balancer / Docker HEALTHCHECK)
	startTime := time.Now()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		status := "healthy"
		xdpLoaded := mapMgr != nil
		if !xdpLoaded {
			status = "degraded"
		}

		geoIPStatus := map[string]bool{}
		if geoIPMgr != nil {
			geoIPMgr.mu.RLock()
			geoIPStatus["asn"] = geoIPMgr.asnLoaded
			geoIPStatus["country"] = geoIPMgr.countryLoaded
			geoIPMgr.mu.RUnlock()
		}

		var sysInfo syscall.Sysinfo_t
		syscall.Sysinfo(&sysInfo)

		// Đếm Process (Bỏ qua thread, chỉ đếm Process trong /proc)
		procsCount := 0
		if dirEntries, err := os.ReadDir("/proc"); err == nil {
			for _, entry := range dirEntries {
				if entry.IsDir() && entry.Name()[0] >= '0' && entry.Name()[0] <= '9' {
					procsCount++
				}
			}
		} else {
			procsCount = int(sysInfo.Procs)
		}

		// Đọc RAM chuẩn xác từ /proc/meminfo để match với lệnh "free"
		var totalRam, usedRam, freeRam uint64
		if data, err := os.ReadFile("/proc/meminfo"); err == nil {
			lines := strings.Split(string(data), "\n")
			var memTotal, memFree, buffers, cached, sReclaimable uint64
			for _, line := range lines {
				if strings.HasPrefix(line, "MemTotal:") {
					fmt.Sscanf(line, "MemTotal: %d", &memTotal)
				} else if strings.HasPrefix(line, "MemFree:") {
					fmt.Sscanf(line, "MemFree: %d", &memFree)
				} else if strings.HasPrefix(line, "Buffers:") {
					fmt.Sscanf(line, "Buffers: %d", &buffers)
				} else if strings.HasPrefix(line, "Cached:") {
					fmt.Sscanf(line, "Cached: %d", &cached)
				} else if strings.HasPrefix(line, "SReclaimable:") {
					fmt.Sscanf(line, "SReclaimable: %d", &sReclaimable)
				}
			}
			totalRam = memTotal * 1024
			// Công thức của 'free': used = total - free - buffers - cache - reclaimable
			usedKB := memTotal - memFree - buffers - cached - sReclaimable
			usedRam = usedKB * 1024
			freeRam = memFree * 1024
		} else {
			// Fallback
			unit := uint64(sysInfo.Unit)
			if unit == 0 {
				unit = 1
			}
			totalRam = uint64(sysInfo.Totalram) * unit
			usedRam = totalRam - (uint64(sysInfo.Freeram) * unit)
			freeRam = uint64(sysInfo.Freeram) * unit
		}

		res := map[string]interface{}{
			"status":     status,
			"uptime_sec": int(time.Since(startTime).Seconds()),
			"xdp_loaded": xdpLoaded,
			"geoip":      geoIPStatus,
			"version":    "1.0.0",
			"system": map[string]interface{}{
				"ram_total": totalRam,
				"ram_used":  usedRam,
				"ram_free":  freeRam,
				"load_1m":   float64(sysInfo.Loads[0]) / 65536.0,
				"procs":     procsCount,
			},
		}
		json.NewEncoder(w).Encode(res)
	})

	// Phục vụ giao diện Web Dashboard (Static files)
	fs := http.FileServer(http.Dir("./web"))
	mux.Handle("/", fs)

	// 1. Tạo TCP listener khi đang chạy quyền root
	listener, err := net.Listen("tcp", config.API.Listen)
	if err != nil {
		log.Fatalf("[CẤU HÌNH] Lỗi mở cổng nghe %s: %v", config.API.Listen, err)
	}

	// 2. Phân quyền các thư mục log và pinned BPF map cho user nobody trước khi hạ quyền
	os.Chown(resolvePath("logs"), 65534, 65534)
	os.Chown(resolvePath("logs/mitigation.log"), 65534, 65534)
	os.Chown("/sys/fs/bpf/shield_core", 65534, 65534)
	os.Chown("/sys/fs/bpf/shield_core/xsks_map", 65534, 65534)
	os.Chown("/sys/fs/bpf/shield_core/a2s_info", 65534, 65534)
	os.Chown("/sys/fs/bpf/shield_core/ip_blacklist_map", 65534, 65534)

	// 3. Thực hiện hạ quyền xuống nobody (UID 65534, GID 65534)
	if os.Getuid() == 0 {
		if err := syscall.Setgid(65534); err != nil {
			log.Printf("[Security] Cảnh báo: Không thể hạ GID xuống nobody: %v", err)
		}
		if err := syscall.Setuid(65534); err != nil {
			log.Printf("[Security] Cảnh báo: Không thể hạ UID xuống nobody: %v", err)
		} else {
			log.Println("[Security] Đã hạ quyền tiến trình thành công xuống user 'nobody'.")
		}
	}

	// HTTP Server với Graceful Shutdown
	server := &http.Server{
		Addr:         config.API.Listen,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("API Server (HTTPS/TLS) lắng nghe tại %s", config.API.Listen)
		if err := server.ServeTLS(listener, certPath, keyPath); err != nil && err != http.ErrServerClosed {
			log.Fatalf("API Server lỗi: %v", err)
		}
	}()

	// Chờ tín hiệu dừng (Ctrl+C / SIGTERM)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Đang tắt Shield-Core Control Plane (graceful shutdown)...")

	// Graceful shutdown API server (chờ tối đa 5 giây cho các request đang xử lý)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("[Shutdown] Lỗi khi tắt API server: %v", err)
	}

	if prog != nil {
		prog.UnpinMaps()
	}
	log.Println("Shield-Core Control Plane đã tắt thành công.")
}

type cpuStats struct {
	user, nice, system, idle, iowait, irq, softirq, steal, guest, guestnice uint64
}

func getMemoryStats() (float64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	lines := strings.Split(string(data), "\n")
	var memTotal, memFree, buffers, cached, sReclaimable uint64
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			fmt.Sscanf(line, "MemTotal: %d", &memTotal)
		} else if strings.HasPrefix(line, "MemFree:") {
			fmt.Sscanf(line, "MemFree: %d", &memFree)
		} else if strings.HasPrefix(line, "Buffers:") {
			fmt.Sscanf(line, "Buffers: %d", &buffers)
		} else if strings.HasPrefix(line, "Cached:") {
			fmt.Sscanf(line, "Cached: %d", &cached)
		} else if strings.HasPrefix(line, "SReclaimable:") {
			fmt.Sscanf(line, "SReclaimable: %d", &sReclaimable)
		}
	}
	if memTotal == 0 {
		return 0, fmt.Errorf("không tìm thấy MemTotal")
	}
	usedKB := memTotal - memFree - buffers - cached - sReclaimable
	return float64(usedKB) / float64(memTotal) * 100.0, nil
}

func getCPUStats() (cpuStats, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuStats{}, err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "cpu" {
			if len(fields) < 8 {
				return cpuStats{}, fmt.Errorf("không đủ trường dữ liệu cpu trong /proc/stat")
			}
			var vals [10]uint64
			for i := 1; i < len(fields) && i <= 10; i++ {
				v, err := strconv.ParseUint(fields[i], 10, 64)
				if err != nil {
					return cpuStats{}, err
				}
				vals[i-1] = v
			}
			return cpuStats{
				user:      vals[0],
				nice:      vals[1],
				system:    vals[2],
				idle:      vals[3],
				iowait:    vals[4],
				irq:       vals[5],
				softirq:   vals[6],
				steal:     vals[7],
				guest:     vals[8],
				guestnice: vals[9],
			}, nil
		}
	}
	return cpuStats{}, fmt.Errorf("không tìm thấy dòng cpu")
}

func getQueueStats(iface string) (uint64, uint64, error) {
	dropData, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/rx_dropped", iface))
	if err != nil {
		return 0, 0, err
	}
	pktData, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/rx_packets", iface))
	if err != nil {
		return 0, 0, err
	}
	var drops, packets uint64
	fmt.Sscanf(strings.TrimSpace(string(dropData)), "%d", &drops)
	fmt.Sscanf(strings.TrimSpace(string(pktData)), "%d", &packets)
	return drops, packets, nil
}

func calculateCPUUsage(prev, curr cpuStats) float64 {
	prevIdle := prev.idle + prev.iowait
	currIdle := curr.idle + curr.iowait

	prevNonIdle := prev.user + prev.nice + prev.system + prev.irq + prev.softirq + prev.steal
	currNonIdle := curr.user + curr.nice + curr.system + curr.irq + curr.softirq + curr.steal

	prevTotal := prevIdle + prevNonIdle
	currTotal := currIdle + currNonIdle

	totalDiff := currTotal - prevTotal
	if totalDiff == 0 {
		return 0.0
	}
	idleDiff := currIdle - prevIdle

	return float64(totalDiff-idleDiff) / float64(totalDiff) * 100.0
}

// startAutoMitigation chạy vòng lặp quét IP spam và tự động cách ly (FSM 6 Level)
func startAutoMitigation() {
	log.Println("Đang khởi động Auto-Mitigation Engine v2.1 (SRE Edition)...")

	var prevCPU cpuStats
	if stats, err := getCPUStats(); err == nil {
		prevCPU = stats
	}

	iface := os.Getenv("SHIELD_IFACE")
	if iface == "" {
		iface = "eth0"
	}

	// Reset prevDrops/prevPkts từ giá trị hiện tại để tránh false-positive drop ratio ngay khi khởi động
	var prevDrops, prevPkts uint64
	if d, p, err := getQueueStats(iface); err == nil {
		prevDrops = d
		prevPkts = p
	}
	// Warm-up 3s: Ignore first 3 cycles to let drop ratio stabilize
	warmupCycles := 3

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	currentLevel := 0
	levelHoldTime := 0 // Dùng để làm Asymmetric Hysteresis / Recovery Cooldown

	for range ticker.C {
		if mapMgr == nil {
			continue
		}
		// Warm-up: bỏ qua thiếu số chu kỳ đầu để drop ratio khởi tạo chuẩn
		if warmupCycles > 0 {
			warmupCycles--
			if d, p, err := getQueueStats(iface); err == nil {
				prevDrops = d
				prevPkts = p
			}
			continue
		}

		cpuPercent := 0.0
		ramPercent := 0.0
		queueDropRatio := 0.0

		if currCPU, err := getCPUStats(); err == nil {
			cpuPercent = calculateCPUUsage(prevCPU, currCPU)
			prevCPU = currCPU
		}

		if currRam, err := getMemoryStats(); err == nil {
			ramPercent = currRam
		}

		if currDrops, currPkts, err := getQueueStats(iface); err == nil {
			deltaDrops := currDrops - prevDrops
			deltaPkts := currPkts - prevPkts
			// Bảo vệ vòng lặp phản hồi: chỉ tính drop ratio khi có ít nhất 100 packet
			// Tránh false-positive khi server ít traffic mà drop 1-2 packet = 100%
			if deltaDrops+deltaPkts >= 100 {
				queueDropRatio = float64(deltaDrops) / float64(deltaDrops+deltaPkts)
			} else {
				queueDropRatio = 0.0 // Không đủ lưu lượng mẫu, bỏ qua
			}
			prevDrops = currDrops
			prevPkts = currPkts
		}

		// Map Health Awareness
		healths := mapMgr.GetMapHealth()
		maxMapUsage := 0.0
		for _, h := range healths {
			if h.Name == "ip_stats_map" || h.Name == "ip_blacklist_map" {
				if h.UsagePct > maxMapUsage {
					maxMapUsage = h.UsagePct
				}
			}
		}

		// Ring Pressure Awareness
		var maxRingPct uint32 = 0
		if ringStats, err := mapMgr.GetRingStats(); err == nil {
			if ringStats.RxFillPct > maxRingPct {
				maxRingPct = ringStats.RxFillPct
			}
			if ringStats.TxFillPct > maxRingPct {
				maxRingPct = ringStats.TxFillPct
			}
			if ringStats.FillRingPct > maxRingPct {
				maxRingPct = ringStats.FillRingPct
			}
			if ringStats.CompletionRingPct > maxRingPct {
				maxRingPct = ringStats.CompletionRingPct
			}

			// Export Prometheus metrics
			metricRxRingPressure.Set(float64(ringStats.RxFillPct))
			metricTxRingPressure.Set(float64(ringStats.TxFillPct))
			metricFillRingPressure.Set(float64(ringStats.FillRingPct))
			metricCompRingPressure.Set(float64(ringStats.CompletionRingPct))
		}

		// Tính toán Level cho từng thành phần (Max Calculation)
		levelCPU, levelRAM, levelQueue, levelMap, levelRing := 0, 0, 0, 0, 0

		if cpuPercent > 95.0 {
			levelCPU = 4
		} else if cpuPercent > 90.0 {
			levelCPU = 3
		} else if cpuPercent > 80.0 {
			levelCPU = 2
		} else if cpuPercent > 60.0 {
			levelCPU = 1
		}
		if ramPercent > 95.0 {
			levelRAM = 4
		} else if ramPercent > 92.0 {
			levelRAM = 3
		} else if ramPercent > 85.0 {
			levelRAM = 2
		} else if ramPercent > 70.0 {
			levelRAM = 1
		}
		if queueDropRatio > 0.10 {
			levelQueue = 4
		} else if queueDropRatio > 0.05 {
			levelQueue = 3
		} else if queueDropRatio > 0.03 {
			levelQueue = 2
		} else if queueDropRatio > 0.01 {
			levelQueue = 1
		}
		if maxMapUsage > 95.0 {
			levelMap = 4
		} else if maxMapUsage > 90.0 {
			levelMap = 3
		} else if maxMapUsage > 80.0 {
			levelMap = 2
		} else if maxMapUsage > 60.0 {
			levelMap = 1
		}
		if maxRingPct > 95 {
			levelRing = 4
		} else if maxRingPct > 90 {
			levelRing = 3
		} else if maxRingPct > 80 {
			levelRing = 2
		} else if maxRingPct > 60 {
			levelRing = 1
		}

		targetLevel := levelCPU
		if levelRAM > targetLevel {
			targetLevel = levelRAM
		}
		if levelQueue > targetLevel {
			targetLevel = levelQueue
		}
		if levelMap > targetLevel {
			targetLevel = levelMap
		}
		if levelRing > targetLevel {
			targetLevel = levelRing
		}

		// Emergency Trigger (Bỏ qua Hysteresis, Survival ngay lập tức)
		// queueDropRatio ngưỡng 0.50 (50%) để tránh NIC fluctuation bình thường kích hoạt Emergency
		emergency := false
		if cpuPercent > 98.0 || ramPercent > 98.0 || maxMapUsage > 99.0 || queueDropRatio > 0.50 || maxRingPct > 98 {
			targetLevel = 4
			emergency = true
		}

		// Cơ chế Asymmetric Hysteresis & Recovery
		if emergency && currentLevel != 4 {
			currentLevel = 4
			levelHoldTime = 30 // Giữ survival tối thiểu 30s
			metricSurvivalActivations.Inc()
			log.Printf("[FSM] EMERGENCY TRIGGER! Ép buộc Survival (Level 4) ngay lập tức! (CPU: %.1f%%, RAM: %.1f%%, Map: %.1f%%, Drop: %.1f%%, Ring: %d%%)", cpuPercent, ramPercent, maxMapUsage, queueDropRatio*100, maxRingPct)
		} else if targetLevel > currentLevel {
			if currentLevel == 5 {
				// Đang Recovery mà bị tấn công lại -> Cancel Recovery, nhảy lên Level mới ngay
				currentLevel = targetLevel
				levelHoldTime = 5
				log.Printf("[FSM] Tấn công tái diễn! Huỷ Recovery, tăng Level %d (CPU: %.1f%%)", currentLevel, cpuPercent)
			} else {
				if levelHoldTime > 0 {
					levelHoldTime--
				} else {
					currentLevel = targetLevel
					levelHoldTime = 5 // Promote: Giữ 5s
					log.Printf("[FSM] Tăng Level phòng thủ lên %d", currentLevel)
				}
			}
		} else if targetLevel < currentLevel {
			if levelHoldTime > 0 {
				levelHoldTime--
			} else {
				if currentLevel > 0 && currentLevel <= 4 && targetLevel == 0 {
					currentLevel = 5   // Recovery
					levelHoldTime = 60 // Cooldown 60s
					log.Printf("[FSM] Mức nguy hiểm đã qua, vào trạng thái Recovery (Level 5) đếm ngược 60s")
				} else if currentLevel == 5 {
					currentLevel = 0
					levelHoldTime = 0
					log.Printf("[FSM] Kết thúc Recovery, trở về Normal (Level 0)")
				} else {
					currentLevel = targetLevel
					levelHoldTime = 30 // Demote: Giữ 30s
					log.Printf("[FSM] Hạ nhiệt độ phòng thủ xuống Level %d", currentLevel)
				}
			}
		}

		// Export Metrics
		metricMitigationLevel.Set(float64(currentLevel))
		metricCPUUsage.Set(cpuPercent)
		metricRAMUsage.Set(ramPercent)
		metricMapUsage.Set(maxMapUsage)
		metricQueueDropRatio.Set(queueDropRatio)

		// Áp dụng chính sách dựa trên Level
		currentPPSThreshold := uint64(5000)
		currentBPSThreshold := uint64(10 * 1024 * 1024)
		ttl := uint64(3600) // 1 hour TTL default

		switch currentLevel {
		case 1:
			currentPPSThreshold = 3000
			currentBPSThreshold = 5 * 1024 * 1024
		case 2:
			currentPPSThreshold = 1000
			currentBPSThreshold = 2 * 1024 * 1024
			ttl = 14400 // 4 hours
		case 3:
			currentPPSThreshold = 500
			currentBPSThreshold = 1 * 1024 * 1024 // 1 MB/s
			ttl = 86400                           // 24 hours
		case 4:
			currentPPSThreshold = 300
			currentBPSThreshold = 500 * 1024 // 500 KB/s
			ttl = 86400                      // 24 hours
		case 5:
			currentPPSThreshold = 3000
			currentBPSThreshold = 5 * 1024 * 1024
			ttl = 3600
		}

		// Adaptive Scan Budget
		scanBudget := 500
		switch currentLevel {
		case 1:
			scanBudget = 1000
		case 2:
			scanBudget = 2500
		case 3:
			scanBudget = 5000
		case 4:
			scanBudget = 10000
		case 5:
			scanBudget = 2000
		}
		// Cắt giảm budget nếu CPU quá cao để tránh bồi thêm tải vào CPU
		if cpuPercent > 90.0 && scanBudget > 3000 {
			scanBudget = 3000
		}
		metricScanBudget.Set(float64(scanBudget))

		// Cập nhật ngưỡng động vào eBPF config_map
		if err := mapMgr.UpdateRateLimits(currentPPSThreshold, currentBPSThreshold); err != nil {
			log.Printf("[Auto-Mitigation] Lỗi cập nhật config_map: %v", err)
		}

		// Quét dọn / Mitigate
		blockedIPs, err := mapMgr.ScanAndMitigate(currentPPSThreshold, currentBPSThreshold, scanBudget)
		if err != nil {
			log.Printf("[Auto-Mitigation] Lỗi quét map: %v", err)
			continue
		}
		for _, ip := range blockedIPs {
			log.Printf("[Auto-Mitigation] ĐÃ CHẶN IP NGUỒN TẤN CÔNG (Spam vượt ngưỡng %d PPS): %s", currentPPSThreshold, ip)
			syncIPEvent("blacklist", http.MethodPost, ip)
			writeMitigationLog("mitigation_block", ip, "Traffic threshold exceeded", currentPPSThreshold)
		}

		// Aggressive Age-out khi RAM hoặc CPU cao (Level >= 3)
		if currentLevel >= 3 {
			// Thu dọn mạnh hơn, giảm thời gian TTL
			ttl = 300 // Các IP cũ nếu bị chặn quá 5 phút sẽ được thả để cứu bộ nhớ
		}

		// [Blacklist TTL/Expiry] Quét và tự động mở khóa IP hết hạn block
		blacklistCount := mapMgr.GetBlacklistCount()
		if blacklistCount > 58982 { // 90% của 65536
			log.Printf("[Map Protection] Cảnh báo: ip_blacklist_map gần đầy (%d/65536). Kích hoạt dọn dẹp khẩn cấp, hạ TTL xuống 5 phút.", blacklistCount)
			ttl = 300 // 5 phút (300 giây)
		}

		expiredIPs, err := mapMgr.CleanExpiredBlacklist(ttl)
		if err == nil && len(expiredIPs) > 0 {
			for _, ip := range expiredIPs {
				log.Printf("[Blacklist Expiry] Đã tự động mở khóa IP hết hạn: %s", ip)
				writeMitigationLog("auto_unblock", ip, "Blacklist TTL expired", 0)
				mapMgr.RemoveBlacklistTarget(ip)
				if strings.HasSuffix(ip, "/32") {
					mapMgr.RemoveBlacklistTarget(strings.TrimSuffix(ip, "/32"))
				}
				// Đồng bộ sự kiện mở khoá tới các node khác
				syncIPEvent("blacklist", http.MethodDelete, ip)
			}
			saveRulesState()
		}
	}
}

// handlePrometheusMetrics xuất số liệu dạng Prometheus
func handlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	if mapMgr != nil {
		pass, drop, err := mapMgr.GetStats()
		if err == nil {
			fmt.Fprintf(w, "# HELP shield_core_packets_passed_total Tổng số lượng gói tin hợp lệ đi qua\n")
			fmt.Fprintf(w, "# TYPE shield_core_packets_passed_total counter\n")
			fmt.Fprintf(w, "shield_core_packets_passed_total %d\n", pass)

			fmt.Fprintf(w, "# HELP shield_core_packets_dropped_total Tổng số lượng gói tin bị chặn\n")
			fmt.Fprintf(w, "# TYPE shield_core_packets_dropped_total counter\n")
			fmt.Fprintf(w, "shield_core_packets_dropped_total %d\n", drop)
		}

		// Thống kê theo VIP khách hàng (Multi-tenant)
		vipStats, err := mapMgr.GetVipStats()
		if err == nil {
			fmt.Fprintf(w, "# HELP shield_core_vip_packets_total Tổng số lượng gói tin theo VIP khách hàng\n")
			fmt.Fprintf(w, "# TYPE shield_core_vip_packets_total counter\n")
			for vip, s := range vipStats {
				fmt.Fprintf(w, "shield_core_vip_packets_total{vip=\"%s\", action=\"pass\"} %d\n", vip, s.Passed)
				fmt.Fprintf(w, "shield_core_vip_packets_total{vip=\"%s\", action=\"drop\"} %d\n", vip, s.Dropped)
			}
		}
	}

	// Xuất thông số GeoIP/ASN (Production-Grade Observability)
	if geoIPMgr != nil {
		geoIPMgr.mu.RLock()
		var asnVal, countryVal int
		if geoIPMgr.asnLoaded {
			asnVal = 1
		}
		if geoIPMgr.countryLoaded {
			countryVal = 1
		}

		fmt.Fprintf(w, "# HELP shield_core_geoip_asn_loaded Trạng thái nạp ASN Database (1=Loaded, 0=Not Loaded)\n")
		fmt.Fprintf(w, "# TYPE shield_core_geoip_asn_loaded gauge\n")
		fmt.Fprintf(w, "shield_core_geoip_asn_loaded %d\n", asnVal)

		fmt.Fprintf(w, "# HELP shield_core_geoip_country_loaded Trạng thái nạp Country Database (1=Loaded, 0=Not Loaded)\n")
		fmt.Fprintf(w, "# TYPE shield_core_geoip_country_loaded gauge\n")
		fmt.Fprintf(w, "shield_core_geoip_country_loaded %d\n", countryVal)

		fmt.Fprintf(w, "# HELP shield_core_geoip_asn_size_bytes Kích thước file ASN Database dạng bytes\n")
		fmt.Fprintf(w, "# TYPE shield_core_geoip_asn_size_bytes gauge\n")
		fmt.Fprintf(w, "shield_core_geoip_asn_size_bytes %d\n", geoIPMgr.asnSize)

		fmt.Fprintf(w, "# HELP shield_core_geoip_country_size_bytes Kích thước file Country Database dạng bytes\n")
		fmt.Fprintf(w, "# TYPE shield_core_geoip_country_size_bytes gauge\n")
		fmt.Fprintf(w, "shield_core_geoip_country_size_bytes %d\n", geoIPMgr.countrySize)

		fmt.Fprintf(w, "# HELP shield_core_geoip_cache_entries_total Số lượng bản ghi cache GeoIP hiện tại\n")
		fmt.Fprintf(w, "# TYPE shield_core_geoip_cache_entries_total gauge\n")
		cacheSize := len(geoIPMgr.asnCache) + len(geoIPMgr.countryCache)
		fmt.Fprintf(w, "shield_core_geoip_cache_entries_total %d\n", cacheSize)

		fmt.Fprintf(w, "# HELP shield_core_geoip_cache_hits_total Tổng số lượt tìm trúng cache\n")
		fmt.Fprintf(w, "# TYPE shield_core_geoip_cache_hits_total counter\n")
		fmt.Fprintf(w, "shield_core_geoip_cache_hits_total %d\n", atomic.LoadUint64(&geoIPMgr.cacheHits))

		fmt.Fprintf(w, "# HELP shield_core_geoip_cache_misses_total Tổng số lượt tìm trượt cache\n")
		fmt.Fprintf(w, "# TYPE shield_core_geoip_cache_misses_total counter\n")
		fmt.Fprintf(w, "shield_core_geoip_cache_misses_total %d\n", atomic.LoadUint64(&geoIPMgr.cacheMisses))

		geoIPMgr.mu.RUnlock()
	}

	// Xuất thông số BPF Map Health (Exhaustion Detection)
	if mapMgr != nil {
		fmt.Fprintf(w, "# HELP shield_core_blacklist_entries Số lượng IP trong blacklist hiện tại\n")
		fmt.Fprintf(w, "# TYPE shield_core_blacklist_entries gauge\n")
		fmt.Fprintf(w, "shield_core_blacklist_entries %d\n", mapMgr.GetBlacklistCount())

		mapHealth := mapMgr.GetMapHealth()
		fmt.Fprintf(w, "# HELP shield_core_map_usage_percent Phần trăm sử dụng BPF Map\n")
		fmt.Fprintf(w, "# TYPE shield_core_map_usage_percent gauge\n")
		for _, mh := range mapHealth {
			if mh.Entries >= 0 {
				fmt.Fprintf(w, "shield_core_map_usage_percent{map=\"%s\"} %.2f\n", mh.Name, mh.UsagePct)
			}
		}
		fmt.Fprintf(w, "# HELP shield_core_map_max_entries Dung lượng tối đa BPF Map\n")
		fmt.Fprintf(w, "# TYPE shield_core_map_max_entries gauge\n")
		for _, mh := range mapHealth {
			fmt.Fprintf(w, "shield_core_map_max_entries{map=\"%s\"} %d\n", mh.Name, mh.MaxEntries)
		}
	}

	// Xuất các metrics từ Prometheus client
	promhttp.Handler().ServeHTTP(w, r)
}

// --- Các API Handlers ---

func handleBlacklist(w http.ResponseWriter, r *http.Request) {
	if mapMgr == nil {
		http.Error(w, "XDP Program chưa được nạp", http.StatusServiceUnavailable)
		return
	}

	if r.Method == http.MethodGet {
		targets := mapMgr.GetBlacklistTargets()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(targets)
		return
	}

	target := r.URL.Query().Get("target") // IP, CIDR, hoặc Mã Quốc Gia (VN, US)
	if target == "" {
		target = r.URL.Query().Get("ip")
	}
	if target == "" {
		http.Error(w, "Thiếu tham số target", http.StatusBadRequest)
		return
	}

	var cidrs []string
	if len(target) == 2 && !strings.Contains(target, ".") {
		// Xử lý như Country Code
		if geoIPMgr != nil {
			resolved, err := geoIPMgr.GetCountryCIDRs(strings.ToUpper(target))
			if err != nil || len(resolved) == 0 {
				http.Error(w, "Không tìm thấy CIDR cho Quốc gia này", http.StatusNotFound)
				return
			}
			cidrs = resolved
		} else {
			http.Error(w, "GeoIP DB chưa tải", http.StatusServiceUnavailable)
			return
		}
	} else if !strings.Contains(target, "/") {
		// Thêm /32 cho IP lẻ
		cidrs = []string{target + "/32"}
	} else {
		cidrs = []string{target}
	}

	switch r.Method {
	case "POST":
		successCount := 0
		for _, c := range cidrs {
			if err := mapMgr.BlockCIDR(c); err == nil {
				successCount++
			}
		}
		mapMgr.AddBlacklistTarget(target)
		saveRulesState()
		fmt.Fprintf(w, "Đã thêm %d dải mạng cho target %s vào danh sách đen\n", successCount, target)
		writeMitigationLog("BLACKLIST_ADD", target, "User manually blacklisted", 0)

		if r.URL.Query().Get("sync") != "true" {
			syncIPEvent("blacklist", http.MethodPost, target)
		}

	case "DELETE":
		successCount := 0
		for _, c := range cidrs {
			if err := mapMgr.AllowCIDR(c); err == nil {
				successCount++
			}
		}
		mapMgr.RemoveBlacklistTarget(target)
		saveRulesState()
		fmt.Fprintf(w, "Đã xoá %d dải mạng cho target %s khỏi danh sách đen\n", successCount, target)
		writeMitigationLog("BLACKLIST_REMOVE", target, "User manually un-blacklisted", 0)

		if r.URL.Query().Get("sync") != "true" {
			syncIPEvent("blacklist", http.MethodDelete, target)
		}

	default:
		http.Error(w, "Method không được hỗ trợ", http.StatusMethodNotAllowed)
	}
}

func handleRouting(w http.ResponseWriter, r *http.Request) {
	if mapMgr == nil {
		http.Error(w, "XDP Program chưa được nạp", http.StatusServiceUnavailable)
		return
	}

	if r.Method == http.MethodGet {
		routes, err := mapMgr.GetRoutingMap()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(routes)
		return
	} else if r.Method == http.MethodPost {
		vip := r.URL.Query().Get("vip")
		backend := r.URL.Query().Get("backend")
		tunnelType := r.URL.Query().Get("type")
		if vip == "" || backend == "" {
			http.Error(w, "Thiếu tham số vip hoặc backend", http.StatusBadRequest)
			return
		}

		if err := mapMgr.AddBackendVIP(vip, backend, tunnelType); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("Đã map VIP " + vip + " -> Backend " + backend + " (" + tunnelType + ")"))
	} else if r.Method == http.MethodDelete {
		vip := r.URL.Query().Get("vip")
		backend := r.URL.Query().Get("backend") // Cần backend để xoá iptables rule
		tunnelType := r.URL.Query().Get("type")
		if vip == "" {
			http.Error(w, "Thiếu tham số vip", http.StatusBadRequest)
			return
		}
		if err := mapMgr.RemoveBackendVIP(vip, backend, tunnelType); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("Đã xoá map VIP " + vip))
	} else {
		http.Error(w, "Method không hỗ trợ", http.StatusMethodNotAllowed)
	}
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	if mapMgr == nil {
		http.Error(w, "XDP Program chưa được nạp", http.StatusServiceUnavailable)
		return
	}

	pass, drop, err := mapMgr.GetStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := map[string]uint64{
		"pass_count": pass,
		"drop_count": drop,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

type ReputationItem struct {
	CIDR        string `json:"cidr"`
	Score       int    `json:"score"`
	Description string `json:"description"`
}

func loadReputationDatabase(filePath string) {
	if mapMgr == nil {
		return
	}
	log.Printf("Đang nạp cơ sở dữ liệu IP Reputation từ %s...", filePath)
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("[Reputation] Không thể đọc file: %v. Bỏ qua nạp danh tiếng IP.", err)
		return
	}

	var items []ReputationItem
	if err := json.Unmarshal(data, &items); err != nil {
		log.Printf("[Reputation] Lỗi parse JSON: %v", err)
		return
	}

	loadedCount := 0
	for _, item := range items {
		if item.Score >= 80 {
			if err := mapMgr.BlockCIDR(item.CIDR); err != nil {
				log.Printf("[Reputation] Lỗi nạp %s (%s): %v", item.CIDR, item.Description, err)
			} else {
				loadedCount++
			}
		}
	}
	log.Printf("[Reputation] Đã nạp thành công %d/%d dải IP uy tín thấp vào CIDR Blacklist LPM Trie", loadedCount, len(items))
}

var clusterNodes []string

func loadClusterNodes(filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("[Sync] Không thể đọc file nodes.json: %v. Không kích hoạt cụm sync.", err)
		return
	}
	if err := json.Unmarshal(data, &clusterNodes); err != nil {
		log.Printf("[Sync] Lỗi parse JSON nodes.json: %v", err)
	} else {
		log.Printf("[Sync] Đã nạp %d nodes trong cụm để thực hiện đồng bộ.", len(clusterNodes))
	}
}

// isLocalAddress kiểm tra xem URL của node có trỏ tới chính máy này hay không.
func isLocalAddress(nodeUrl string) bool {
	u, err := url.Parse(nodeUrl)
	if err != nil {
		cleaned := strings.TrimPrefix(nodeUrl, "http://")
		cleaned = strings.TrimPrefix(cleaned, "https://")
		hostPort := strings.Split(cleaned, "/")[0]
		host, port, err := net.SplitHostPort(hostPort)
		if err != nil {
			host = hostPort
			port = ""
		}
		return isHostAndPortLocal(host, port)
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
		port = ""
	}
	return isHostAndPortLocal(host, port)
}

func isHostAndPortLocal(host, port string) bool {
	localPort := "9090" // Giá trị mặc định nếu không parse được listenAddr
	_, p, err := net.SplitHostPort(listenAddr)
	if err == nil {
		localPort = p
	} else {
		cleanedListen := strings.TrimPrefix(listenAddr, ":")
		if _, errIsNum := strconv.Atoi(cleanedListen); errIsNum == nil {
			localPort = cleanedListen
		}
	}

	if port != "" && port != localPort {
		return false
	}

	// Localhost luôn là local node
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}

	// Lấy danh sách IP các interface trên máy
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok {
			if ipNet.IP.String() == host {
				return true
			}
		}
	}

	// Kiểm tra hostname của hệ thống
	if hostname, err := os.Hostname(); err == nil && hostname == host {
		return true
	}

	return false
}

func syncIPEvent(endpoint string, method string, ip string) {
	for _, node := range clusterNodes {
		if isLocalAddress(node) {
			log.Printf("[Sync] Bỏ qua gửi sync event tới chính nó (local node: %s)", node)
			continue
		}
		go func(nodeUrl string) {
			// Đảm bảo sử dụng HTTPS
			secureNodeUrl := strings.Replace(nodeUrl, "http://", "https://", 1)
			if !strings.HasPrefix(secureNodeUrl, "https://") {
				secureNodeUrl = "https://" + secureNodeUrl
			}
			urlStr := fmt.Sprintf("%s/api/%s?target=%s&sync=true", secureNodeUrl, endpoint, url.QueryEscape(ip))
			req, err := http.NewRequest(method, urlStr, nil)
			if err != nil {
				log.Printf("[Sync -> %s] Lỗi tạo request: %v", secureNodeUrl, err)
				return
			}
			req.Header.Set("X-API-Key", configuredAPIKey)

			// Tạo TLS transport hỗ trợ chứng chỉ tự ký
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client := &http.Client{
				Transport: tr,
				Timeout:   2 * time.Second,
			}

			resp, err := client.Do(req)
			if err != nil {
				log.Printf("[Sync -> %s] Lỗi gửi sync event: %v", secureNodeUrl, err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode >= 400 {
				log.Printf("[Sync -> %s] [CẢNH BÁO] Đồng bộ %s cho %s (IP: %s) THẤT BẠI: Status %d", secureNodeUrl, method, endpoint, ip, resp.StatusCode)
			} else {
				log.Printf("[Sync -> %s] Đã đồng bộ sự kiện %s cho %s (IP: %s) (Status: %d)", secureNodeUrl, method, endpoint, ip, resp.StatusCode)
			}
		}(node)
	}
}

func syncGeoRuleEvent(method string, ruleType string, value string) {
	if len(clusterNodes) == 0 {
		return
	}
	for _, node := range clusterNodes {
		if isLocalAddress(node) {
			continue
		}
		go func(n string) {
			targetUrl := fmt.Sprintf("%s/api/rules/%s?%s=%s&sync=true", n, ruleType, ruleType, value)
			req, err := http.NewRequest(method, targetUrl, nil)
			if err != nil {
				return
			}
			req.Header.Set("X-API-Key", configuredAPIKey)
			client := &http.Client{
				Timeout: 5 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("[Sync Geo -> %s] Lỗi: %v", n, err)
				return
			}
			defer resp.Body.Close()
			log.Printf("[Sync Geo -> %s] Đã đồng bộ sự kiện %s cho %s=%s (Status: %d)", n, method, ruleType, value, resp.StatusCode)
		}(node)
	}
}

func syncGeoPolicyEvent(action string) {
	if len(clusterNodes) == 0 {
		return
	}
	for _, node := range clusterNodes {
		if isLocalAddress(node) {
			continue
		}
		go func(n string) {
			targetUrl := fmt.Sprintf("%s/api/rules/policy?action=%s&sync=true", n, action)
			req, err := http.NewRequest(http.MethodPost, targetUrl, nil)
			if err != nil {
				return
			}
			req.Header.Set("X-API-Key", configuredAPIKey)
			client := &http.Client{
				Timeout: 5 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}(node)
	}
}



func handleGeoIPHealth(w http.ResponseWriter, r *http.Request) {
	if geoIPMgr == nil {
		http.Error(w, "GeoIP Manager chưa được khởi tạo", http.StatusServiceUnavailable)
		return
	}

	geoIPMgr.mu.RLock()
	defer geoIPMgr.mu.RUnlock()

	res := map[string]interface{}{
		"asn_db_loaded":      geoIPMgr.asnLoaded,
		"country_db_loaded":  geoIPMgr.countryLoaded,
		"last_reload_time":   geoIPMgr.lastReloadTime.Format(time.RFC3339),
		"asn_db_size":        geoIPMgr.asnSize,
		"country_db_size":    geoIPMgr.countrySize,
		"asn_db_version":     geoIPMgr.asnVersion,
		"country_db_version": geoIPMgr.countryVersion,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func handleGeoIPReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Chỉ hỗ trợ HTTP POST", http.StatusMethodNotAllowed)
		return
	}
	if geoIPMgr == nil {
		http.Error(w, "GeoIP Manager chưa được khởi tạo", http.StatusServiceUnavailable)
		return
	}
	log.Println("[GeoIP] Đang yêu cầu tải nóng (Hot Reload) cơ sở dữ liệu...")
	geoIPMgr.Reload()
	w.Write([]byte("Đã thực hiện tải lại cơ sở dữ liệu GeoIP/ASN."))
}

type MitigationEvent struct {
	Timestamp string `json:"timestamp"`
	Event     string `json:"event"`
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	Value     uint64 `json:"value"`
}

func writeMitigationLog(event string, ip string, reason string, value uint64) {
	logDir := resolvePath("logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Printf("[Log] Không thể tạo thư mục logs: %v", err)
		return
	}

	logPath := filepath.Join(logDir, "mitigation.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[Log] Không thể mở file log: %v", err)
		return
	}
	defer f.Close()

	ev := MitigationEvent{
		Timestamp: time.Now().Format(time.RFC3339),
		Event:     event,
		IP:        ip,
		Reason:    reason,
		Value:     value,
	}

	jsonData, err := json.Marshal(ev)
	if err != nil {
		log.Printf("[Log] Lỗi marshal JSON event: %v", err)
		return
	}

	if _, err := f.Write(append(jsonData, '\n')); err != nil {
		log.Printf("[Log] Lỗi ghi log: %v", err)
	}
}

// handleWhitelist API
func handleWhitelist(w http.ResponseWriter, r *http.Request) {
	if mapMgr == nil {
		http.Error(w, "Map Manager chưa sẵn sàng", http.StatusServiceUnavailable)
		return
	}

	if r.Method == "GET" {
		targets := mapMgr.GetWhitelistTargets()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(targets)
		return
	}

	target := r.URL.Query().Get("target") // IP, CIDR, hoặc Mã Quốc Gia (VN, US)
	if target == "" {
		target = r.URL.Query().Get("ip")
	}
	if target == "" {
		http.Error(w, "Thiếu tham số target", http.StatusBadRequest)
		return
	}

	var cidrs []string
	if len(target) == 2 && !strings.Contains(target, ".") {
		// Xử lý như Country Code
		if geoIPMgr != nil {
			resolved, err := geoIPMgr.GetCountryCIDRs(strings.ToUpper(target))
			if err != nil || len(resolved) == 0 {
				http.Error(w, "Không tìm thấy CIDR cho Quốc gia này", http.StatusNotFound)
				return
			}
			cidrs = resolved
		} else {
			http.Error(w, "GeoIP DB chưa tải", http.StatusServiceUnavailable)
			return
		}
	} else if !strings.Contains(target, "/") {
		// Thêm /32 cho IP lẻ
		cidrs = []string{target + "/32"}
	} else {
		cidrs = []string{target}
	}

	switch r.Method {
	case "POST":
		successCount := 0
		for _, c := range cidrs {
			if err := mapMgr.AddWhitelistCIDR(c); err == nil {
				successCount++
			}
		}
		mapMgr.AddWhitelistTarget(target)
		saveRulesState()
		fmt.Fprintf(w, "Đã thêm %d dải mạng cho target %s vào Whitelist\n", successCount, target)
		writeMitigationLog("WHITELIST_ADD", target, "User added to whitelist", 0)

		if r.URL.Query().Get("sync") != "true" {
			syncIPEvent("whitelist", http.MethodPost, target)
		}
	case "DELETE":
		successCount := 0
		for _, c := range cidrs {
			if err := mapMgr.RemoveWhitelistCIDR(c); err == nil {
				successCount++
			}
		}
		mapMgr.RemoveWhitelistTarget(target)

		// Kiểm tra nếu danh sách whitelist trống, tự động fallback về Blacklist (Default Pass / policy = 0)
		whitelistEmpty := len(mapMgr.GetWhitelistTargets()) == 0
		if whitelistEmpty {
			log.Printf("[Whitelist] Danh sách Whitelist trống sau khi xoá %s, tự động fallback GeoIP Policy về 0 (Default Pass)", target)
			mapMgr.SetGeoIPPolicy(0)
			writeMitigationLog("POLICY_UPDATE", "0", "Auto fallback to blacklist (Default Pass) because whitelist is empty", 0)
		}

		saveRulesState()
		fmt.Fprintf(w, "Đã xoá %d dải mạng cho target %s khỏi Whitelist\n", successCount, target)
		writeMitigationLog("WHITELIST_REMOVE", target, "User removed from whitelist", 0)

		if r.URL.Query().Get("sync") != "true" {
			syncIPEvent("whitelist", http.MethodDelete, target)
			if whitelistEmpty {
				syncGeoPolicyEvent("0")
			}
		}
	default:
		http.Error(w, "Method không được hỗ trợ", http.StatusMethodNotAllowed)
	}
}

// handleRulesPolicy API
func handleRulesPolicy(w http.ResponseWriter, r *http.Request) {
	if mapMgr == nil {
		http.Error(w, "Map Manager chưa sẵn sàng", http.StatusServiceUnavailable)
		return
	}

	if r.Method == "GET" {
		policy, err := mapMgr.GetGeoIPPolicy()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]uint64{"policy": policy})
		return
	}

	if r.Method == "POST" {
		action := r.URL.Query().Get("action")
		var policy uint64
		if action == "1" || action == "drop" {
			policy = 1
		} else if action == "0" || action == "pass" {
			policy = 0
		} else {
			http.Error(w, "Action không hợp lệ (hỗ trợ: 0, 1, pass, drop)", http.StatusBadRequest)
			return
		}

		err := mapMgr.SetGeoIPPolicy(policy)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		
		saveRulesState()

		policyStr := "Default Pass (Chỉ chặn Blacklist)"
		if policy == 1 {
			policyStr = "Default Drop (Chỉ cho phép Whitelist)"
		}

		fmt.Fprintf(w, "Đã cập nhật GeoIP Policy thành: %s\n", policyStr)
		writeMitigationLog("POLICY_UPDATE", fmt.Sprintf("%d", policy), "User updated GeoIP Policy", 0)

		if r.URL.Query().Get("sync") != "true" {
			syncGeoPolicyEvent(fmt.Sprintf("%d", policy))
		}
		return
	}

	http.Error(w, "Method không được hỗ trợ", http.StatusMethodNotAllowed)
}

// handleLogs API
func handleLogs(w http.ResponseWriter, r *http.Request) {
	logDir := resolvePath("logs")
	logPath := filepath.Join(logDir, "mitigation.log")

	// Trả về mảng JSON rỗng nếu chưa có log
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}

	// Đọc toàn bộ file và lấy tối đa 100 dòng mới nhất
	data, err := os.ReadFile(logPath)
	if err != nil {
		http.Error(w, "Không thể đọc log", http.StatusInternalServerError)
		return
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var result []json.RawMessage

	// Đọc từ cuối lên
	for i := len(lines) - 1; i >= 0 && len(result) < 100; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			result = append(result, json.RawMessage(line))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

