package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

// MapManager xử lý các logic đọc/ghi trực tiếp vào BPF Map
type MapManager struct {
	prog            *XDPProgram
	activeCountries map[string]bool
	activeASNs      map[string]bool
	
	// Track user-configured targets directly (IP, CIDR, or Country Code)
	WhitelistTargets map[string]bool
	BlacklistTargets map[string]bool

	sync.RWMutex
}

func NewMapManager(prog *XDPProgram) *MapManager {
	return &MapManager{
		prog:             prog,
		activeCountries:  make(map[string]bool),
		activeASNs:       make(map[string]bool),
		WhitelistTargets: make(map[string]bool),
		BlacklistTargets: make(map[string]bool),
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

func (m *MapManager) updateWhitelistCount() {
	count := len(m.activeCountries) + len(m.activeASNs)
	if m.prog.objs.ConfigMap != nil {
		var key uint32 = 3
		m.prog.objs.ConfigMap.Put(key, uint64(count))
	}
}

func (m *MapManager) AddActiveCountry(countryCode string) {
	m.Lock()
	m.activeCountries[countryCode] = true
	m.updateWhitelistCount()
	m.Unlock()
}

func (m *MapManager) RemoveActiveCountry(countryCode string) {
	m.Lock()
	delete(m.activeCountries, countryCode)
	m.updateWhitelistCount()
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
	m.updateWhitelistCount()
	m.Unlock()
}

func (m *MapManager) RemoveActiveASN(asn string) {
	m.Lock()
	delete(m.activeASNs, asn)
	m.updateWhitelistCount()
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

// BlockCIDR thêm IP/Subnet vào danh sách đen
func (m *MapManager) BlockCIDR(cidrStr string) error {
	ipVal, prefixLen, err := parseCIDR(cidrStr)
	if err != nil {
		return err
	}

	key := LpmTrieKey{
		PrefixLen: prefixLen,
		Data:      ipVal,
	}
	val := uint64(time.Now().Unix())
	err = m.prog.objs.CidrBlacklist.Put(key, val)
	if err != nil {
		return fmt.Errorf("lỗi ghi vào cidr blacklist: %v", err)
	}
	return nil
}

// AllowCIDR xoá IP/Subnet khỏi danh sách đen
func (m *MapManager) AllowCIDR(cidrStr string) error {
	ipVal, prefixLen, err := parseCIDR(cidrStr)
	if err != nil {
		return err
	}

	key := LpmTrieKey{
		PrefixLen: prefixLen,
		Data:      ipVal,
	}
	err = m.prog.objs.CidrBlacklist.Delete(key)
	if err != nil {
		return fmt.Errorf("lỗi xoá khỏi cidr blacklist: %v", err)
	}
	return nil
}

// AddWhitelistCIDR thêm IP/Subnet vào danh sách trắng
func (m *MapManager) AddWhitelistCIDR(cidrStr string) error {
	ipVal, prefixLen, err := parseCIDR(cidrStr)
	if err != nil {
		return err
	}

	key := LpmTrieKey{
		PrefixLen: prefixLen,
		Data:      ipVal,
	}
	var val uint64 = 1
	err = m.prog.objs.CidrWhitelist.Put(key, val)
	if err != nil {
		return fmt.Errorf("lỗi ghi vào cidr whitelist: %v", err)
	}
	return nil
}

// RemoveWhitelistCIDR xoá IP/Subnet khỏi danh sách trắng
func (m *MapManager) RemoveWhitelistCIDR(cidrStr string) error {
	ipVal, prefixLen, err := parseCIDR(cidrStr)
	if err != nil {
		return err
	}

	key := LpmTrieKey{
		PrefixLen: prefixLen,
		Data:      ipVal,
	}
	err = m.prog.objs.CidrWhitelist.Delete(key)
	if err != nil {
		return fmt.Errorf("lỗi xoá khỏi cidr whitelist: %v", err)
	}
	return nil
}

// FormatLpmKey format lpm_trie_key_t to string CIDR
func formatLpmKey(key LpmTrieKey) string {
	ipBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipBytes, key.Data)
	ip := net.IP(ipBytes).String()
	if key.PrefixLen == 32 {
		return ip
	}
	return fmt.Sprintf("%s/%d", ip, key.PrefixLen)
}

// GetWhitelistCIDRs lấy danh sách whitelist
func (m *MapManager) GetWhitelistCIDRs() ([]string, error) {
	var cidrs []string
	var key LpmTrieKey
	var val uint64

	iter := m.prog.objs.CidrWhitelist.Iterate()
	for iter.Next(&key, &val) {
		cidrs = append(cidrs, formatLpmKey(key))
	}
	return cidrs, iter.Err()
}

// GetBlacklistCIDRs lấy danh sách blacklist
func (m *MapManager) GetBlacklistCIDRs() ([]string, error) {
	var cidrs []string
	var key LpmTrieKey
	var val uint64

	iter := m.prog.objs.CidrBlacklist.Iterate()
	for iter.Next(&key, &val) {
		cidrs = append(cidrs, formatLpmKey(key))
	}
	return cidrs, iter.Err()
}

// --- Target Management ---

func (m *MapManager) AddWhitelistTarget(target string) {
	m.Lock()
	m.WhitelistTargets[target] = true
	m.Unlock()
}

func (m *MapManager) RemoveWhitelistTarget(target string) {
	m.Lock()
	delete(m.WhitelistTargets, target)
	m.Unlock()
}

func (m *MapManager) GetWhitelistTargets() []string {
	m.RLock()
	defer m.RUnlock()
	list := make([]string, 0, len(m.WhitelistTargets))
	for k := range m.WhitelistTargets {
		list = append(list, k)
	}
	return list
}

func (m *MapManager) AddBlacklistTarget(target string) {
	m.Lock()
	m.BlacklistTargets[target] = true
	m.Unlock()
}

func (m *MapManager) RemoveBlacklistTarget(target string) {
	m.Lock()
	delete(m.BlacklistTargets, target)
	m.Unlock()
}

func (m *MapManager) GetBlacklistTargets() []string {
	m.RLock()
	defer m.RUnlock()
	list := make([]string, 0, len(m.BlacklistTargets))
	for k := range m.BlacklistTargets {
		list = append(list, k)
	}
	return list
}

type BackendKey struct {
	Vip      uint32
	Vport    uint16
	Protocol uint8
	Pad      uint8
}

type BackendInfo struct {
	IP   uint32
	Port uint16
	Type uint8
	Pad  uint8
}

func htons(val uint16) uint16 {
	return (val << 8) | (val >> 8)
}

func ntohs(val uint16) uint16 {
	return (val << 8) | (val >> 8)
}

func addWireGuardPeer(pubkey string, allowedIP string, endpoint string) {
	if pubkey == "" || allowedIP == "" {
		return
	}
	// 1. Cấu hình nóng bằng lệnh wg set
	args := []string{"set", "wg0", "peer", pubkey, "allowed-ips", allowedIP + "/32"}
	if endpoint != "" {
		args = append(args, "endpoint", endpoint)
	}
	exec.Command("wg", args...).Run()

	// 2. Ghi vào file /etc/wireguard/wg0.conf để lưu trữ vĩnh viễn
	confPath := "/etc/wireguard/wg0.conf"
	data, err := os.ReadFile(confPath)
	if err == nil {
		content := string(data)
		if !strings.Contains(content, pubkey) {
			peerConfig := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n", pubkey, allowedIP)
			if endpoint != "" {
				peerConfig += fmt.Sprintf("Endpoint = %s\n", endpoint)
			}
			peerConfig += "PersistentKeepalive = 25\n"

			f, err := os.OpenFile(confPath, os.O_APPEND|os.O_WRONLY, 0600)
			if err == nil {
				f.WriteString(peerConfig)
				f.Close()
			}
		}
	}
}

func removeWireGuardPeer(pubkey string) {
	if pubkey == "" {
		return
	}
	// 1. Cấu hình nóng xóa peer
	exec.Command("wg", "set", "wg0", "peer", pubkey, "remove").Run()

	// 2. Xóa khỏi file /etc/wireguard/wg0.conf
	confPath := "/etc/wireguard/wg0.conf"
	data, err := os.ReadFile(confPath)
	if err == nil {
		content := string(data)
		if strings.Contains(content, pubkey) {
			lines := strings.Split(content, "\n")
			var newLines []string
			inPeerBlock := false
			var peerBlock []string

			for i := 0; i < len(lines); i++ {
				line := lines[i]
				if strings.HasPrefix(strings.TrimSpace(line), "[Peer]") {
					if inPeerBlock {
						if !blockContains(peerBlock, pubkey) {
							newLines = append(newLines, peerBlock...)
						}
					}
					inPeerBlock = true
					peerBlock = []string{line}
				} else if inPeerBlock {
					if strings.HasPrefix(strings.TrimSpace(line), "[Interface]") {
						inPeerBlock = false
						if !blockContains(peerBlock, pubkey) {
							newLines = append(newLines, peerBlock...)
						}
						newLines = append(newLines, line)
					} else {
						peerBlock = append(peerBlock, line)
					}
				} else {
					newLines = append(newLines, line)
				}
			}
			if inPeerBlock && !blockContains(peerBlock, pubkey) {
				newLines = append(newLines, peerBlock...)
			}

			os.WriteFile(confPath, []byte(strings.Join(newLines, "\n")), 0600)
		}
	}
}

func blockContains(block []string, target string) bool {
	for _, l := range block {
		if strings.Contains(l, target) {
			return true
		}
	}
	return false
}

// AddBackendVIP map Front-end VIP với Backend IP/Port (IPIP hoặc WireGuard)
func (m *MapManager) AddBackendVIP(vipStr string, vport uint16, protocol uint8, backendStr string, tunnelType string, pubkey string, endpoint string) error {
	vipKey, err := ipToUint32(vipStr)
	if err != nil {
		return err
	}

	backendIPStr := backendStr
	var backendPort uint16 = 0
	if strings.Contains(backendStr, ":") {
		parts := strings.Split(backendStr, ":")
		backendIPStr = parts[0]
		p, err := strconv.ParseUint(parts[1], 10, 16)
		if err == nil {
			backendPort = uint16(p)
		}
	}

	backendVal, err := ipToUint32(backendIPStr)
	if err != nil {
		return err
	}

	var tType uint8 = 0 // IPIP
	if tunnelType == "wireguard" {
		tType = 1

		// Tự động add peer WireGuard trên VPS
		if pubkey != "" {
			addWireGuardPeer(pubkey, backendIPStr, endpoint)
		}

		// Thiết lập iptables DNAT cho WireGuard (BỎ QUA cổng 22 SSH và 9090 API)
		// Định tuyến TCP
		exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-d", vipStr, "-p", "tcp", "-m", "multiport", "!", "--dports", "22,9090", "-j", "DNAT", "--to-destination", backendStr).Run()
		// Định tuyến UDP
		exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-d", vipStr, "-p", "udp", "-j", "DNAT", "--to-destination", backendStr).Run()
		// Định tuyến ICMP (Ping)
		exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-d", vipStr, "-p", "icmp", "-j", "DNAT", "--to-destination", backendIPStr).Run()
	}

	key := BackendKey{
		Vip:      vipKey,
		Vport:    htons(vport),
		Protocol: protocol,
		Pad:      0,
	}

	info := BackendInfo{
		IP:   backendVal,
		Port: htons(backendPort),
		Type: tType,
		Pad:  0,
	}

	err = m.prog.objs.BackendMap.Put(key, info)
	if err != nil {
		return fmt.Errorf("lỗi khi ghi VIP vào backend map: %v", err)
	}
	return nil
}

func (m *MapManager) RemoveBackendVIP(vipStr string, vport uint16, protocol uint8, backendStr string, tunnelType string, pubkey string) error {
	vipKey, err := ipToUint32(vipStr)
	if err != nil {
		return err
	}

	backendIPStr := backendStr
	if strings.Contains(backendStr, ":") {
		backendIPStr = strings.Split(backendStr, ":")[0]
	}

	if tunnelType == "wireguard" {
		if pubkey != "" {
			removeWireGuardPeer(pubkey)
		}

		if backendIPStr != "" {
			// Gỡ bỏ iptables
			exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-d", vipStr, "-p", "tcp", "-m", "multiport", "!", "--dports", "22,9090", "-j", "DNAT", "--to-destination", backendStr).Run()
			exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-d", vipStr, "-p", "udp", "-j", "DNAT", "--to-destination", backendStr).Run()
			exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-d", vipStr, "-p", "icmp", "-j", "DNAT", "--to-destination", backendIPStr).Run()
		}
	}

	// 1. Thử xóa key cụ thể trước nếu có vport
	if vport != 0 {
		key := BackendKey{
			Vip:      vipKey,
			Vport:    htons(vport),
			Protocol: protocol,
			Pad:      0,
		}
		deleteErr := m.prog.objs.BackendMap.Delete(key)
		if deleteErr == nil {
			return nil
		}
	}

	// 2. Fallback: Nếu không tìm thấy key cụ thể hoặc không truyền vport, duyệt map và xóa tất cả các key trùng VIP này
	var k BackendKey
	var v BackendInfo
	var keysToDelete []BackendKey
	iter := m.prog.objs.BackendMap.Iterate()
	for iter.Next(&k, &v) {
		if k.Vip == vipKey {
			keysToDelete = append(keysToDelete, k)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("lỗi duyệt map khi xóa: %v", err)
	}

	for _, keyToDelete := range keysToDelete {
		m.prog.objs.BackendMap.Delete(keyToDelete)
	}

	return nil
}

type RoutingEntry struct {
	VIP         string `json:"vip"`
	VPort       uint16 `json:"vport"`
	Protocol    string `json:"protocol"`
	BackendIP   string `json:"backend_ip"`
	BackendPort uint16 `json:"backend_port"`
	TunnelType  string `json:"tunnel_type"`
}

func (m *MapManager) GetRoutingMap() ([]RoutingEntry, error) {
	var routes []RoutingEntry
	var key BackendKey
	var val BackendInfo

	iter := m.prog.objs.BackendMap.Iterate()
	for iter.Next(&key, &val) {
		vipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(vipBytes, key.Vip)

		backendBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(backendBytes, val.IP)
		
		tType := "ipip"
		if val.Type == 1 {
			tType = "wireguard"
		}

		protoStr := "any"
		if key.Protocol == 6 {
			protoStr = "tcp"
		} else if key.Protocol == 17 {
			protoStr = "udp"
		}

		routes = append(routes, RoutingEntry{
			VIP:         net.IP(vipBytes).String(),
			VPort:       ntohs(key.Vport),
			Protocol:    protoStr,
			BackendIP:   net.IP(backendBytes).String(),
			BackendPort: ntohs(val.Port),
			TunnelType:  tType,
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
func (m *MapManager) ScanAndMitigate(ppsThreshold uint64, bpsThreshold uint64, scanLimit int) ([]string, error) {
	var key uint32
	type statVal struct {
		PPS        uint64
		BPS        uint64
		NextUpdate uint64
	}
	var vals []statVal

	var blockedIPs []string

	iter := m.prog.objs.IpStatsMap.Iterate()
	count := 0
	for iter.Next(&key, &vals) {
		count++
		if scanLimit > 0 && count > scanLimit {
			break
		}
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

			// Block CIDR (/32) trong 1 giờ
			if err := m.BlockCIDR(ipStr); err == nil {
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

// CleanExpiredBlacklist quét cidr_blacklist_map và xóa các entry đã hết hạn (vượt quá ttlSeconds)
func (m *MapManager) CleanExpiredBlacklist(ttlSeconds uint64) ([]string, error) {
	var key LpmTrieKey
	var val uint64
	var expiredCIDRs []string
	nowUnix := uint64(time.Now().Unix())

	iter := m.prog.objs.CidrBlacklist.Iterate()
	for iter.Next(&key, &val) {
		// val lưu Unix timestamp (giây) thời điểm block
		// Nếu val = 0 hoặc val = 1 (entry cũ trước khi có TTL), bỏ qua để tránh xóa nhầm
		if val <= 1 {
			continue
		}
		if nowUnix-val > ttlSeconds {
			cidrStr := formatLpmKey(key)
			m.prog.objs.CidrBlacklist.Delete(key)
			expiredCIDRs = append(expiredCIDRs, cidrStr)
		}
	}
	return expiredCIDRs, iter.Err()
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
		{"cidr_blacklist_map", m.prog.objs.CidrBlacklist},
		{"cidr_whitelist_map", m.prog.objs.CidrWhitelist},
		{"ip_stats_map", m.prog.objs.IpStatsMap},
		{"backend_map", m.prog.objs.BackendMap},
		{"stats_map", m.prog.objs.StatsMap},
		{"a2s_info", m.prog.objs.A2sInfo},
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
		case "cidr_blacklist_map":
			var k LpmTrieKey
			var v uint64
			iter := m.prog.objs.CidrBlacklist.Iterate()
			for iter.Next(&k, &v) {
				count++
			}
		case "backend_map":
			var k BackendKey
			var v BackendInfo
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

// GetBlacklistCount đếm số entries trong CIDR blacklist map
func (m *MapManager) GetBlacklistCount() int {
	var key LpmTrieKey
	var val uint64
	count := 0
	iter := m.prog.objs.CidrBlacklist.Iterate()
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

type RingStatsVal struct {
	RxFillPct         uint32
	TxFillPct         uint32
	FillRingPct       uint32
	CompletionRingPct uint32
	TimestampNs       uint64
}

// GetRingStats đọc thông số Ring Pressure từ AF_XDP
func (m *MapManager) GetRingStats() (RingStatsVal, error) {
	var val RingStatsVal
	if m.prog.objs.RingStatsMap == nil {
		return val, fmt.Errorf("RingStatsMap chưa được nạp")
	}
	var key uint32 = 0
	err := m.prog.objs.RingStatsMap.Lookup(&key, &val)
	return val, err
}
