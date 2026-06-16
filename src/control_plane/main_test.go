package main

import (
	"net"
	"testing"
)

func TestIsLocalAddress(t *testing.T) {
	listenAddr = ":9090" // Set listen address global variable

	// Find an actual local IP address to test
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("Không thể lấy danh sách interface addrs: %v", err)
	}

	var localIP string
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			localIP = ipNet.IP.String()
			break
		}
	}

	tests := []struct {
		url      string
		expected bool
	}{
		{"http://localhost:9090", true},
		{"http://127.0.0.1:9090", true},
		{"https://127.0.0.1:9090", true},
		{"http://127.0.0.1:8080", false}, // Wrong port
		{"http://google.com:9090", false}, // External domain
		{"http://1.1.1.1:9090", false},    // External IP
	}

	if localIP != "" {
		tests = append(tests, struct {
			url      string
			expected bool
		}{"http://" + localIP + ":9090", true})
		tests = append(tests, struct {
			url      string
			expected bool
		}{"http://" + localIP + ":9091", false}) // Wrong port on local IP
	}

	for _, tc := range tests {
		result := isLocalAddress(tc.url)
		if result != tc.expected {
			t.Errorf("isLocalAddress(%q) = %v; mong đợi %v", tc.url, result, tc.expected)
		}
	}
}
