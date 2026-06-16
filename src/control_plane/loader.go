package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// XDPProgram đại diện cho cấu trúc quản lý BPF Program và Maps
type XDPProgram struct {
	objs      *bpfObjects
	ifaceName string
}

// Struct ánh xạ với các object trong file ELF compile ra từ C
type bpfObjects struct {
	XdpProgMain      *ebpf.Program `ebpf:"xdp_prog_main"`
	IpBlacklist      *ebpf.Map     `ebpf:"ip_blacklist_map"`
	IpWhitelist      *ebpf.Map     `ebpf:"ip_whitelist_map"`
	IpStatsMap       *ebpf.Map     `ebpf:"ip_stats_map"`
	BackendMap       *ebpf.Map     `ebpf:"backend_map"`
	StatsMap         *ebpf.Map     `ebpf:"stats_map"`
	XsksMap          *ebpf.Map     `ebpf:"xsks_map"`
	A2sInfo          *ebpf.Map     `ebpf:"a2s_info"`
	AsnBlacklist     *ebpf.Map     `ebpf:"asn_blacklist_map"`
	CountryBlacklist *ebpf.Map     `ebpf:"country_blacklist_map"`
	VipStats         *ebpf.Map     `ebpf:"vip_stats_map"`
	LocalPorts       *ebpf.Map     `ebpf:"local_ports_map"`
	ConfigMap        *ebpf.Map     `ebpf:"config_map"`
}

func LoadXDPProgram(ifaceName string, objPath string) (*XDPProgram, error) {
	// Lấy thông tin Interface qua netlink
	link_dev, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("không tìm thấy interface %s: %v", ifaceName, err)
	}

	// Đọc file ELF (.o)
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("lỗi khi đọc file BPF ELF: %v", err)
	}

	// Load objects vào Kernel và pin các Map
	objs := &bpfObjects{}
	err = spec.LoadAndAssign(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf/shield_core",
		},
	})
	if err != nil {
		if ve, ok := err.(*ebpf.VerifierError); ok {
			log.Printf("VERIFIER LOG:\n%s\n", strings.Join(ve.Log, "\n"))
		}
		return nil, fmt.Errorf("lỗi khi load BPF object vào kernel: %v", err)
	}

	const (
		XDP_FLAGS_UPDATE_IF_NOEXIST = 1
		XDP_FLAGS_SKB_MODE          = 2
		XDP_FLAGS_DRV_MODE          = 4
	)

	// Xóa XDP cũ (nếu có) để tránh lỗi file exists
	netlink.LinkSetXdpFdWithFlags(link_dev, -1, 0)

	// Xóa XDP cũ (nếu có) để tránh lỗi file exists
	netlink.LinkSetXdpFdWithFlags(link_dev, -1, 0)
	
	// Tạo thư mục pin nếu chưa có
	os.MkdirAll("/sys/fs/bpf/shield_core", 0755)

	// Ghim các BPF Maps dùng chung với AF_XDP
	objs.XsksMap.Pin("/sys/fs/bpf/shield_core/xsks_map")
	objs.A2sInfo.Pin("/sys/fs/bpf/shield_core/a2s_info")
	objs.IpBlacklist.Pin("/sys/fs/bpf/shield_core/ip_blacklist_map")

	// Xóa XDP cũ (nếu có) để tránh lỗi file exists
	netlink.LinkSetXdpFdWithFlags(link_dev, -1, 0)
	
	// Thử Driver Mode trước
	err = netlink.LinkSetXdpFdWithFlags(link_dev, objs.XdpProgMain.FD(), XDP_FLAGS_DRV_MODE)
	if err != nil {
		log.Printf("[XDP] Driver Mode thất bại (%v), fallback về Generic/SKB Mode...", err)
		err = netlink.LinkSetXdpFdWithFlags(link_dev, objs.XdpProgMain.FD(), XDP_FLAGS_SKB_MODE)
		if err != nil {
			return nil, fmt.Errorf("lỗi khi attach XDP: %v", err)
		}
		log.Printf("Đã gắn Shield-Core XDP vào %s [chế độ: GENERIC/SKB]", ifaceName)
	} else {
		log.Printf("Đã gắn Shield-Core XDP vào %s [chế độ: DRIVER/NATIVE]", ifaceName)
	}

	return &XDPProgram{
		objs:      objs,
		ifaceName: ifaceName,
	}, nil
}

func (x *XDPProgram) Close() {
	if x.ifaceName != "" {
		// Detach XDP program from interface
		link_dev, err := netlink.LinkByName(x.ifaceName)
		if err == nil {
			netlink.LinkSetXdpFd(link_dev, -1)
		}
	}
}

func (x *XDPProgram) UnpinMaps() {
	log.Println("Đang dọn dẹp BPF Pinned Maps tại /sys/fs/bpf/shield_core...")
	os.RemoveAll("/sys/fs/bpf/shield_core")
}

