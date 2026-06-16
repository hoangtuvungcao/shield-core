package main

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
)

// RulesState lưu toàn bộ trạng thái rule để persist ra disk
type RulesState struct {
	GeoIPPolicy      uint64   `json:"geoip_policy"`
	BlacklistTargets []string `json:"blacklist_targets"`
	WhitelistTargets []string `json:"whitelist_targets"`
}

var (
	stateFilePath string
	stateMutex    sync.Mutex
)

func initPersistence() {
	stateFilePath = resolvePath("conf/rules_state.json")
}

// saveRulesState ghi state hiện tại ra file. Gọi sau mỗi thay đổi.
func saveRulesState() {
	if mapMgr == nil || stateFilePath == "" {
		return
	}

	stateMutex.Lock()
	defer stateMutex.Unlock()

	policy, _ := mapMgr.GetGeoIPPolicy()

	state := RulesState{
		GeoIPPolicy:      policy,
		BlacklistTargets: mapMgr.GetBlacklistTargets(),
		WhitelistTargets: mapMgr.GetWhitelistTargets(),
	}

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

// applyTargetToMap expands the target and applies it to the BPF maps
func applyTargetToMap(target string, isWhitelist bool) {
	var cidrs []string
	if len(target) == 2 && !strings.Contains(target, ".") {
		if geoIPMgr != nil {
			resolved, err := geoIPMgr.GetCountryCIDRs(strings.ToUpper(target))
			if err == nil && len(resolved) > 0 {
				cidrs = resolved
			}
		}
	} else if !strings.Contains(target, "/") {
		cidrs = []string{target + "/32"}
	} else {
		cidrs = []string{target}
	}

	for _, c := range cidrs {
		if isWhitelist {
			mapMgr.AddWhitelistCIDR(c)
		} else {
			mapMgr.BlockCIDR(c)
		}
	}
}

// restoreRulesState đọc state từ file và nạp lại vào eBPF maps khi startup
func restoreRulesState() {
	if mapMgr == nil || stateFilePath == "" {
		return
	}

	stateMutex.Lock()
	defer stateMutex.Unlock()

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

	// Restore Policy
	mapMgr.SetGeoIPPolicy(state.GeoIPPolicy)
	log.Printf("[Persist] ✓ Khôi phục GeoIP Policy: %d", state.GeoIPPolicy)

	// Restore Blacklist
	for _, target := range state.BlacklistTargets {
		mapMgr.AddBlacklistTarget(target)
		applyTargetToMap(target, false)
		restored++
	}
	if len(state.BlacklistTargets) > 0 {
		log.Printf("[Persist] ✓ Khôi phục %d mục vào Blacklist", len(state.BlacklistTargets))
	}

	// Restore Whitelist
	for _, target := range state.WhitelistTargets {
		mapMgr.AddWhitelistTarget(target)
		applyTargetToMap(target, true)
		restored++
	}
	if len(state.WhitelistTargets) > 0 {
		log.Printf("[Persist] ✓ Khôi phục %d mục vào Whitelist", len(state.WhitelistTargets))
	}

	log.Printf("[Persist] Hoàn thành khôi phục: %d mục.", restored)
}
