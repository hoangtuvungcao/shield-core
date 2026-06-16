package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"
)

// RulesState lưu toàn bộ trạng thái rule để persist ra disk
type RulesState struct {
	GeoPolicy   string   `json:"geo_policy"`  // "blacklist" | "whitelist"
	Countries   []string `json:"countries"`   // Mã quốc gia đang active
	ASNs        []string `json:"asns"`        // ASN đang active (số, không có prefix AS)
	IPBlacklist []string `json:"ip_blacklist"` // IP bị chặn
	IPWhitelist []string `json:"ip_whitelist"` // IP được ưu tiên
}

var stateFilePath string

func initPersistence(basePath string) {
	stateFilePath = filepath.Join(basePath, "conf", "rules_state.json")
}

// saveRulesState ghi state hiện tại ra file. Gọi sau mỗi thay đổi.
func saveRulesState() {
	if mapMgr == nil || stateFilePath == "" {
		return
	}

	state := RulesState{}

	// Lấy GeoIP Policy
	policy, err := mapMgr.GetGeoIPPolicy()
	if err == nil {
		if policy == 1 {
			state.GeoPolicy = "whitelist"
		} else {
			state.GeoPolicy = "blacklist"
		}
	}

	// Lấy danh sách country và ASN từ in-memory map
	state.Countries = mapMgr.GetActiveCountries()
	state.ASNs = mapMgr.GetActiveASNs()

	// Lấy IP Blacklist từ BPF map
	ipsBl, _ := mapMgr.GetBlacklistIPs()
	state.IPBlacklist = ipsBl

	// Lấy IP Whitelist từ BPF map
	ipsWl, _ := mapMgr.GetWhitelistIPs()
	state.IPWhitelist = ipsWl

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Printf("[Persist] Lỗi marshal state: %v", err)
		return
	}

	if err := os.WriteFile(stateFilePath, data, 0640); err != nil {
		log.Printf("[Persist] Lỗi ghi state file %s: %v", stateFilePath, err)
		return
	}
}

// restoreRulesState đọc state từ file và nạp lại vào eBPF maps khi startup
func restoreRulesState() {
	if mapMgr == nil || stateFilePath == "" {
		return
	}

	data, err := os.ReadFile(stateFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("[Persist] Chưa có state file, bắt đầu với trạng thái trống.")
		} else {
			log.Printf("[Persist] Lỗi đọc state file: %v", err)
		}
		return
	}

	var state RulesState
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("[Persist] Lỗi parse state file: %v", err)
		return
	}

	log.Println("[Persist] Đang khôi phục trạng thái từ file...")
	restored := 0

	// Restore GeoIP Policy
	if state.GeoPolicy == "whitelist" {
		if err := mapMgr.SetGeoIPPolicy(1); err != nil {
			log.Printf("[Persist] Lỗi khôi phục policy: %v", err)
		} else {
			log.Println("[Persist] ✓ GeoIP Policy: Whitelist")
			restored++
		}
	}

	// Restore Countries - gọi lại geoIPMgr để tra CIDRs
	if geoIPMgr != nil {
		for _, cc := range state.Countries {
			cidrs, err := geoIPMgr.GetCountryCIDRs(cc)
			if err != nil || len(cidrs) == 0 {
				log.Printf("[Persist] Cảnh báo: Không tra cứu được CIDR cho quốc gia %s: %v", cc, err)
				continue
			}
			for _, cidr := range cidrs {
				mapMgr.AddCountryBlacklist(cidr)
			}
			mapMgr.AddActiveCountry(cc)
			restored++
		}
		if len(state.Countries) > 0 {
			log.Printf("[Persist] ✓ Khôi phục %d quốc gia: %v", len(state.Countries), state.Countries)
		}

		// Restore ASNs
		for _, asnStr := range state.ASNs {
			asnVal, err := strconv.ParseUint(asnStr, 10, 32)
			if err != nil {
				log.Printf("[Persist] ASN không hợp lệ: %s", asnStr)
				continue
			}
			cidrs, err := geoIPMgr.GetASNCIDRs(uint32(asnVal))
			if err != nil || len(cidrs) == 0 {
				log.Printf("[Persist] Cảnh báo: Không tra cứu được CIDR cho ASN %s: %v", asnStr, err)
				continue
			}
			for _, cidr := range cidrs {
				mapMgr.AddASNBlacklist(cidr)
			}
			mapMgr.AddActiveASN(asnStr)
			restored++
		}
		if len(state.ASNs) > 0 {
			log.Printf("[Persist] ✓ Khôi phục %d ASN: %v", len(state.ASNs), state.ASNs)
		}
	}

	// Restore IP Blacklist
	for _, ip := range state.IPBlacklist {
		mapMgr.BlockIP(ip)
		restored++
	}
	if len(state.IPBlacklist) > 0 {
		log.Printf("[Persist] ✓ Khôi phục %d IP vào Blacklist", len(state.IPBlacklist))
	}

	// Restore IP Whitelist
	for _, ip := range state.IPWhitelist {
		mapMgr.AllowWhitelistIP(ip)
		restored++
	}
	if len(state.IPWhitelist) > 0 {
		log.Printf("[Persist] ✓ Khôi phục %d IP vào Whitelist", len(state.IPWhitelist))
	}

	log.Printf("[Persist] Hoàn thành khôi phục: %d mục.", restored)
}
