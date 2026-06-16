package main

import (
	"encoding/json"
	"log"
	"os"
	"sync"
)

// RulesState lưu toàn bộ trạng thái rule để persist ra disk
type RulesState struct {
	BlacklistCIDRs []string `json:"blacklist_cidrs"`
	WhitelistCIDRs []string `json:"whitelist_cidrs"`
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

	state := RulesState{}

	// Lấy CIDR Blacklist từ BPF map
	cidrsBl, _ := mapMgr.GetBlacklistCIDRs()
	state.BlacklistCIDRs = cidrsBl

	// Lấy CIDR Whitelist từ BPF map
	cidrsWl, _ := mapMgr.GetWhitelistCIDRs()
	state.WhitelistCIDRs = cidrsWl

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

	// Restore Blacklist
	for _, cidr := range state.BlacklistCIDRs {
		mapMgr.BlockCIDR(cidr)
		restored++
	}
	if len(state.BlacklistCIDRs) > 0 {
		log.Printf("[Persist] ✓ Khôi phục %d dải mạng vào Blacklist", len(state.BlacklistCIDRs))
	}

	// Restore Whitelist
	for _, cidr := range state.WhitelistCIDRs {
		mapMgr.AddWhitelistCIDR(cidr)
		restored++
	}
	if len(state.WhitelistCIDRs) > 0 {
		log.Printf("[Persist] ✓ Khôi phục %d dải mạng vào Whitelist", len(state.WhitelistCIDRs))
	}

	log.Printf("[Persist] Hoàn thành khôi phục: %d mục.", restored)
}
