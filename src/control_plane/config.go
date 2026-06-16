package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
)

type Config struct {
	GeoIP struct {
		AsnDBPath     string `json:"asn_db_path"`
		CountryDBPath string `json:"country_db_path"`
	} `json:"geoip"`
	API struct {
		Key    string `json:"api_key"`
		Listen string `json:"listen"`
	} `json:"api"`
}

func LoadConfig(filePath string) (Config, error) {
	var config Config
	data, err := os.ReadFile(filePath)
	if err != nil {
		return config, err
	}
	err = json.Unmarshal(data, &config)

	// Nếu chưa có API key, tự sinh một key an toàn
	if config.API.Key == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err == nil {
			config.API.Key = hex.EncodeToString(key)
			log.Printf("[Security] Tự động sinh API Key: %s", config.API.Key)
			log.Printf("[Security] Hãy lưu key này vào config.json trường api.api_key để sử dụng lâu dài.")
		}
	}

	if config.API.Listen == "" {
		config.API.Listen = ":8080"
	}

	return config, err
}
