.PHONY: all bpf control_plane af_xdp clean mk_build install test

# Biến cấu hình
INSTALL_DIR ?= /opt/shield-core
IFACE ?= eth0
BPF_CFLAGS ?= -O2 -g -target bpf -I src/bpf -I modules/xdp-tools/headers -I /usr/include

all: mk_build bpf control_plane af_xdp

mk_build:
	mkdir -p build

bpf:
	@echo "═══ Building eBPF Datapath ═══"
	clang $(BPF_CFLAGS) -c -o src/bpf/xdp_main.o src/bpf/xdp_main.c
	@echo "✓ BPF program compiled"

control_plane:
	@echo "═══ Building Go Control Plane ═══"
	cd src/control_plane && CGO_ENABLED=0 go build -ldflags="-s -w" -o ../../build/shield-ctrl
	@echo "✓ shield-ctrl built"

af_xdp:
	@echo "═══ Building local libxdp if needed ═══"
	@if [ ! -f modules/xdp-tools/lib/libxdp/libxdp.a ]; then \
		cd modules/xdp-tools && ./configure && make -C lib/libxdp; \
	fi
	@echo "═══ Building AF_XDP Fastpath ═══"
	clang -O2 -g -I src/af_xdp -I modules/xdp-tools/headers -I modules/xdp-tools/lib/libbpf/src/root/include \
		-o build/shield-fastpath src/af_xdp/af_xdp_main.c src/af_xdp/dpi.c \
		modules/xdp-tools/lib/libxdp/libxdp.a \
		modules/xdp-tools/lib/libbpf/src/libbpf.a \
		-lpthread -lelf -lz
	@echo "✓ shield-fastpath built"


test:
	@echo "═══ Running Go Tests ═══"
	cd src/control_plane && go test -v -race ./...

install: all
	@echo "═══ Installing Shield-Core to $(INSTALL_DIR) ═══"
	bash scripts/install.sh

clean:
	@echo "═══ Cleaning up ═══"
	rm -f src/bpf/*.o
	rm -rf build/
	@echo "✓ Clean complete"

# Dev helpers
run-ctrl:
	@echo "═══ Running Control Plane (dev mode) ═══"
	SHIELD_IFACE=$(IFACE) ./build/shield-ctrl

run-fastpath:
	@echo "═══ Running AF_XDP Fastpath (dev mode) ═══"
	sudo ./build/shield-fastpath $(IFACE)

status:
	@echo "═══ Shield-Core Status ═══"
	@curl -sk https://localhost:9090/health 2>/dev/null | python3 -m json.tool || echo "Control Plane not running"
