package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

// MapManager xử lý các logic đọc/ghi trực tiếp vào BPF Map
type MapManager struct {
	prog            *XDPProgram
	activeCountries map[string]bool
	activeASNs      map[string]bool
	sync.RWMutex
}

func NewMapManager(prog *XDPProgram) *MapManager {
	return &MapManager{
		prog:            prog,
		activeCountries: make(map[string]bool),
		activeASNs:      make(map[string]bool),
	}
}

// SetGeoIPPolicy ghi policy (0=Blacklist, 1=Whitelist) vào config_map
func (m *MapManager) SetGeoIPPolicy(policy uint64) error {
	if m.prog.objs.ConfigMap == nil {
		return fmt.Errorf("ConfigMap chưa được nạp")
	}
	var policyKey uint32 = 2
	return m.prog.objs.ConfigMap.Put(policyKey, policy)
}

// GetGeoIPPolicy đọc policy hiện tại
func (m *MapManager) GetGeoIPPolicy() (uint64, error) {
	if m.prog.objs.ConfigMap == nil {
		return 0, fmt.Errorf("ConfigMap chưa được nạp")
	}
	var policyKey uint32 = 2
	var val uint64
	err := m.prog.objs.ConfigMap.Lookup(policyKey, &val)
	if err != nil {
		return 0, nil // Default to Blacklist
	}
	return val, nil
}

func (m *MapManager) AddActiveCountry(countryCode string) {
	m.Lock()
	m.activeCountries[countryCode] = true
	m.Unlock()
}

func (m *MapManager) RemoveActiveCountry(countryCode string) {
	m.Lock()
	delete(m.activeCountries, countryCode)
	m.Unlock()
}

func (m *MapManager) GetActiveCountries() []string {
	m.RLock()
	defer m.RUnlock()
	list := make([]string, 0, len(m.activeCountries))
	for k := range m.activeCountries {
		list = append(list, k)
	}
	return list
}

func (m *MapManager) AddActiveASN(asn string) {
	m.Lock()
	m.activeASNs[asn] = true
	m.Unlock()
}

func (m *MapManager) RemoveActiveASN(asn string) {
	m.Lock()
	delete(m.activeASNs, asn)
	m.Unlock()
}

func (m *MapManager) GetActiveASNs() []string {
	m.RLock()
	defer m.RUnlock()
	list := make([]string, 0, len(m.activeASNs))
	for k := range m.activeASNs {
		list = append(list, k)
	}
	return list
}

// ipToUint32 chuyển đổi IP string thành uint32 theo kiến trúc little-endian của host
func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("IP không hợp lệ: %s", ipStr)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("chỉ hỗ trợ IPv4")
	}
	// iph->saddr là Network Byte Order. Trên máy x86 (little endian), nó được đọc vào u32 theo dạng little endian.
	// Chúng ta ghi trực tiếp 4 bytes vào map bằng cách dùng LittleEndian.Uint32
	return binary.LittleEndian.Uint32(ipv4), nil
}

// BlockIP thêm IP vào danh sách đen với timestamp để hỗ trợ TTL/Expiry
func (m *MapManager) BlockIP(ipStr string) error {
	ipKey, err := ipToUint32(ipStr)
	if err != nil {
		return err
	}

	// Value là u64, lưu Unix timestamp (giây) làm thời điểm block để hỗ trợ tự động hết hạn
	val := uint64(time.Now().Unix())
	err = m.prog.objs.IpBlacklist.Put(ipKey, val)
	if err != nil {
		return fmt.Errorf("lỗi khi ghi IP vào blacklist map: %v", err)
	}
	return nil
}

// AllowIP xoá IP khỏi danh sách đen
func (m *MapManager) AllowIP(ipStr string) error {
	ipKey, err := ipToUint32(ipStr)
	if err != nil {
		return err
	}

	err = m.prog.objs.IpBlacklist.Delete(ipKey)
	if err != nil {
		return fmt.Errorf("lỗi khi xoá IP khỏi blacklist map: %v", err)
	}
	return nil
}

// AllowWhitelistIP thêm IP vào whitelist
func (m *MapManager) AllowWhitelistIP(ipStr string) error {
	ipKey, err := ipToUint32(ipStr)
	if err != nil {
		return err
	}
	var val uint64 = 1
	err = m.prog.objs.IpWhitelist.Put(ipKey, val)
	if err != nil {
		return fmt.Errorf("lỗi khi ghi IP vào whitelist map: %v", err)
	}
	return nil
}

// RemoveWhitelistIP xoá IP khỏi whitelist
func (m *MapManager) RemoveWhitelistIP(ipStr string) error {
	ipKey, err := ipToUint32(ipStr)
	if err != nil {
		return err
	}
	err = m.prog.objs.IpWhitelist.Delete(ipKey)
	if err != nil {
		return fmt.Errorf("lỗi khi xoá IP khỏi whitelist map: %v", err)
	}
	return nil
}

// GetWhitelistIPs lấy danh sách whitelist
func (m *MapManager) GetWhitelistIPs() ([]string, error) {
	var ips []string
	var key uint32
	var val uint64

	iter := m.prog.objs.IpWhitelist.Iterate()
	for iter.Next(&key, &val) {
		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, key)
		ips = append(ips, net.IP(ipBytes).String())
	}
	return ips, iter.Err()
}

// GetBlacklistIPs lấy danh sách tất cả IP đang bị chặn từ BPF map
func (m *MapManager) GetBlacklistIPs() ([]string, error) {
	var ips []string
	var key uint32
	var val uint64

	iter := m.prog.objs.IpBlacklist.Iterate()
	for iter.Next(&key, &val) {
		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, key)
		ips = append(ips, net.IP(ipBytes).String())
	}
	return ips, iter.Err()
}

type BackendInfo struct {
	IP   uint32
	Type uint8
	_    [3]byte // Padding
}

// AddBackendVIP map Front-end VIP với Backend IP (IPIP hoặc WireGuard)
func (m *MapManager) AddBackendVIP(vipStr string, backendStr string, tunnelType string) error {
	vipKey, err := ipToUint32(vipStr)
	if err != nil {
		return err
	}

	backendVal, err := ipToUint32(backendStr)
	if err != nil {
		return err
	}

	var tType uint8 = 0 // IPIP
	if tunnelType == "wireguard" {
		tType = 1

		// Thiết lập iptables DNAT cho WireGuard (BỎ QUA cổng 22 SSH và 9090 API)
		// Định tuyến TCP
		exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-d", vipStr, "-p", "tcp", "-m", "multiport", "!", "--dports", "22,9090", "-j", "DNAT", "--to-destination", backendStr).Run()
		// Định tuyến UDP
		exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-d", vipStr, "-p", "udp", "-j", "DNAT", "--to-destination", backendStr).Run()
		// Định tuyến ICMP (Ping)
		exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-d", vipStr, "-p", "icmp", "-j", "DNAT", "--to-destination", backendStr).Run()
	}

	info := BackendInfo{
		IP:   backendVal,
		Type: tType,
	}

	err = m.prog.objs.BackendMap.Put(vipKey, info)
	if err != nil {
		return fmt.Errorf("lỗi khi ghi VIP vào backend map: %v", err)
	}
	return nil
}

func (m *MapManager) RemoveBackendVIP(vipStr string, backendStr string, tunnelType string) error {
	vipKey, err := ipToUint32(vipStr)
	if err != nil {
		return err
	}

	if tunnelType == "wireguard" && backendStr != "" {
		// Gỡ bỏ iptables
		exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-d", vipStr, "-p", "tcp", "-m", "multiport", "!", "--dports", "22,9090", "-j", "DNAT", "--to-destination", backendStr).Run()
		exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-d", vipStr, "-p", "udp", "-j", "DNAT", "--to-destination", backendStr).Run()
		exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-d", vipStr, "-p", "icmp", "-j", "DNAT", "--to-destination", backendStr).Run()
	}

	return m.prog.objs.BackendMap.Delete(vipKey)
}

type RoutingEntry struct {
	VIP        string `json:"vip"`
	BackendIP  string `json:"backend_ip"`
	TunnelType string `json:"tunnel_type"`
}

func (m *MapManager) GetRoutingMap() ([]RoutingEntry, error) {
	var routes []RoutingEntry
	var key uint32
	var val BackendInfo

	iter := m.prog.objs.BackendMap.Iterate()
	for iter.Next(&key, &val) {
		vipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(vipBytes, key)

		backendBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(backendBytes, val.IP)
		
		tType := "ipip"
		if val.Type == 1 {
			tType = "wireguard"
		}

		routes = append(routes, RoutingEntry{
			VIP:        net.IP(vipBytes).String(),
			BackendIP:  net.IP(backendBytes).String(),
			TunnelType: tType,
		})
	}
	return routes, iter.Err()
}

// GetStats lấy số liệu Drop/Pass
func (m *MapManager) GetStats() (uint64, uint64, error) {
	// stats_map là PERCPU_ARRAY
	// Ở đây tạm đọc tổng số (sum qua các CPU)
	var passKey uint32 = 0
	var dropKey uint32 = 1

	var passValues []uint64
	var dropValues []uint64

	err := m.prog.objs.StatsMap.Lookup(passKey, &passValues)
	if err != nil {
		return 0, 0, err
	}

	err = m.prog.objs.StatsMap.Lookup(dropKey, &dropValues)
	if err != nil {
		return 0, 0, err
	}

	var totalPass uint64
	for _, v := range passValues {
		totalPass += v
	}

	var totalDrop uint64
	for _, v := range dropValues {
		totalDrop += v
	}

	return totalPass, totalDrop, nil
}

// ScanAndMitigate quét map thống kê IP và tự động chặn các IP spam vượt ngưỡng (gộp từ Per-CPU stats)
func (m *MapManager) ScanAndMitigate(ppsThreshold uint64, bpsThreshold uint64) ([]string, error) {
	var key uint32
	type statVal struct {
		PPS        uint64
		BPS        uint64
		NextUpdate uint64
	}
	var vals []statVal

	var blockedIPs []string

	iter := m.prog.objs.IpStatsMap.Iterate()
	for iter.Next(&key, &vals) {
		var totalPPS uint64
		var totalBPS uint64
		for _, v := range vals {
			totalPPS += v.PPS
			totalBPS += v.BPS
		}

		if totalPPS > ppsThreshold || totalBPS > bpsThreshold {
			ipBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(ipBytes, key)
			ipStr := net.IP(ipBytes).String()

			// Block IP trong 1 giờ
			if err := m.BlockIP(ipStr); err == nil {
				blockedIPs = append(blockedIPs, ipStr)
				// Xoá record trong stats map để tránh xử lý lặp lại
				m.prog.objs.IpStatsMap.Delete(key)
			}
		}
	}

	return blockedIPs, iter.Err()
}

// LpmTrieKey đại diện cho key của LPM Trie map
type LpmTrieKey struct {
	PrefixLen uint32
	Data      uint32
}

func parseCIDR(cidrStr string) (uint32, uint32, error) {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		ip := net.ParseIP(cidrStr)
		if ip == nil {
			return 0, 0, fmt.Errorf("CIDR hoặc IP không hợp lệ: %s", cidrStr)
		}
		ipv4 := ip.To4()
		if ipv4 == nil {
			return 0, 0, fmt.Errorf("chỉ hỗ trợ IPv4")
		}
		return binary.LittleEndian.Uint32(ipv4), 32, nil
	}
	ipv4 := ipNet.IP.To4()
	if ipv4 == nil {
		return 0, 0, fmt.Errorf("chỉ hỗ trợ IPv4")
	}
	ones, _ := ipNet.Mask.Size()
	return binary.LittleEndian.Uint32(ipv4), uint32(ones), nil
}

func (m *MapManager) AddASNBlacklist(cidrStr string) error {
	ipVal, prefixLen, err := parseCIDR(cidrStr)
	if err != nil {
		return err
	}
	key := LpmTrieKey{
		PrefixLen: prefixLen,
		Data:      ipVal,
	}
	var val uint64 = 1
	return m.prog.objs.AsnBlacklist.Put(key, val)
}

func (m *MapManager) RemoveASNBlacklist(cidrStr string) error {
	ipVal, prefixLen, err := parseCIDR(cidrStr)
	if err != nil {
		return err
	}
	key := LpmTrieKey{
		PrefixLen: prefixLen,
		Data:      ipVal,
	}
	return m.prog.objs.AsnBlacklist.Delete(key)
}

func (m *MapManager) AddCountryBlacklist(cidrStr string) error {
	ipVal, prefixLen, err := parseCIDR(cidrStr)
	if err != nil {
		return err
	}
	key := LpmTrieKey{
		PrefixLen: prefixLen,
		Data:      ipVal,
	}
	var val uint64 = 1
	return m.prog.objs.CountryBlacklist.Put(key, val)
}



func (m *MapManager) GetASNBlacklists() ([]string, error) {
	var list []string
	var key LpmTrieKey
	var val uint64

	iter := m.prog.objs.AsnBlacklist.Iterate()
	for iter.Next(&key, &val) {
		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, key.Data)
		ipStr := net.IP(ipBytes).String()
		list = append(list, fmt.Sprintf("%s/%d", ipStr, key.PrefixLen))
	}
	return list, iter.Err()
}

func (m *MapManager) GetCountryBlacklists() ([]string, error) {
	var list []string
	var key LpmTrieKey
	var val uint64

	iter := m.prog.objs.CountryBlacklist.Iterate()
	for iter.Next(&key, &val) {
		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, key.Data)
		ipStr := net.IP(ipBytes).String()
		list = append(list, fmt.Sprintf("%s/%d", ipStr, key.PrefixLen))
	}
	return list, iter.Err()
}

func (m *MapManager) RemoveCountryBlacklist(cidrStr string) error {
	ipVal, prefixLen, err := parseCIDR(cidrStr)
	if err != nil {
		return err
	}
	key := LpmTrieKey{
		PrefixLen: prefixLen,
		Data:      ipVal,
	}
	return m.prog.objs.CountryBlacklist.Delete(key)
}

type VipStatsVal struct {
	Passed  uint64
	Dropped uint64
}

// GetVipStats trả về bản đồ chứa thông số lưu lượng của từng VIP khách hàng
func (m *MapManager) GetVipStats() (map[string]VipStatsVal, error) {
	res := make(map[string]VipStatsVal)
	var key uint32
	var val VipStatsVal

	if m.prog.objs.VipStats == nil {
		return res, nil
	}

	iter := m.prog.objs.VipStats.Iterate()
	for iter.Next(&key, &val) {
		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, key)
		ipStr := net.IP(ipBytes).String()
		res[ipStr] = val
	}
	return res, iter.Err()
}

// CleanExpiredBlacklist quét ip_blacklist_map và xóa các entry đã hết hạn (vượt quá ttlSeconds)
func (m *MapManager) CleanExpiredBlacklist(ttlSeconds uint64) ([]string, error) {
	var key uint32
	var val uint64
	var expiredIPs []string
	nowUnix := uint64(time.Now().Unix())

	iter := m.prog.objs.IpBlacklist.Iterate()
	for iter.Next(&key, &val) {
		// val lưu Unix timestamp (giây) thời điểm block
		// Nếu val = 0 hoặc val = 1 (entry cũ trước khi có TTL), bỏ qua để tránh xóa nhầm
		if val <= 1 {
			continue
		}
		if nowUnix-val > ttlSeconds {
			ipBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(ipBytes, key)
			ipStr := net.IP(ipBytes).String()
			m.prog.objs.IpBlacklist.Delete(key)
			expiredIPs = append(expiredIPs, ipStr)
		}
	}
	return expiredIPs, iter.Err()
}

// MapHealthInfo chứa thông tin sức khỏe từng BPF Map
type MapHealthInfo struct {
	Name       string `json:"name"`
	Entries    int    `json:"entries"`
	MaxEntries int    `json:"max_entries"`
	UsagePct   float64 `json:"usage_pct"`
}

// GetMapHealth trả về thông tin sức khỏe tất cả BPF Maps (phát hiện map exhaustion)
func (m *MapManager) GetMapHealth() []MapHealthInfo {
	var health []MapHealthInfo

	maps := []struct {
		name string
		m    interface{ Info() (*ebpf.MapInfo, error) }
	}{
		{"ip_blacklist_map", m.prog.objs.IpBlacklist},
		{"ip_stats_map", m.prog.objs.IpStatsMap},
		{"backend_map", m.prog.objs.BackendMap},
		{"stats_map", m.prog.objs.StatsMap},
		{"a2s_info", m.prog.objs.A2sInfo},
		{"asn_blacklist_map", m.prog.objs.AsnBlacklist},
		{"country_blacklist_map", m.prog.objs.CountryBlacklist},
		{"vip_stats_map", m.prog.objs.VipStats},
	}

	for _, mp := range maps {
		if mp.m == nil {
			continue
		}
		info, err := mp.m.Info()
		if err != nil {
			continue
		}
		maxEntries := int(info.MaxEntries)
		// Đếm số entries hiện tại bằng cách iterate
		count := 0
		switch mp.name {
		case "ip_blacklist_map":
			var k uint32
			var v uint64
			iter := m.prog.objs.IpBlacklist.Iterate()
			for iter.Next(&k, &v) {
				count++
			}
		case "backend_map":
			var k uint32
			var v uint32
			iter := m.prog.objs.BackendMap.Iterate()
			for iter.Next(&k, &v) {
				count++
			}
		default:
			// Cho các map khác, dùng ước tính
			count = -1
		}

		usagePct := 0.0
		if count >= 0 && maxEntries > 0 {
			usagePct = float64(count) / float64(maxEntries) * 100.0
		}
		health = append(health, MapHealthInfo{
			Name:       mp.name,
			Entries:    count,
			MaxEntries: maxEntries,
			UsagePct:   usagePct,
		})
	}
	return health
}

// GetBlacklistCount đếm số entries trong IP blacklist map
func (m *MapManager) GetBlacklistCount() int {
	var key uint32
	var val uint64
	count := 0
	iter := m.prog.objs.IpBlacklist.Iterate()
	for iter.Next(&key, &val) {
		count++
	}
	return count
}

// UpdateRateLimits cập nhật ngưỡng PPS và BPS vào config_map của eBPF
func (m *MapManager) UpdateRateLimits(pps, bps uint64) error {
	if m.prog.objs.ConfigMap == nil {
		return fmt.Errorf("ConfigMap chưa được nạp")
	}

	var ppsKey uint32 = 0
	var bpsKey uint32 = 1

	if err := m.prog.objs.ConfigMap.Put(ppsKey, pps); err != nil {
		return fmt.Errorf("lỗi khi cập nhật pps limit: %v", err)
	}

	if err := m.prog.objs.ConfigMap.Put(bpsKey, bps); err != nil {
		return fmt.Errorf("lỗi khi cập nhật bps limit: %v", err)
	}

	return nil
}
