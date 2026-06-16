## ===========================
## Shield-Core Production Build
## Multi-stage Dockerfile
## ===========================

# ----- Stage 1: Build eBPF C programs -----
FROM ubuntu:24.04 AS bpf-builder

# Thiết lập non-interactive
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev libelf-dev linux-headers-generic \
    make gcc pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY src/bpf/ src/bpf/
COPY modules/ modules/
COPY Makefile .

RUN mkdir -p build && \
    clang -O2 -g -target bpf \
    -I src/bpf -I modules/xdp-tools/headers -I /usr/include \
    -c -o src/bpf/xdp_main.o src/bpf/xdp_main.c

# ----- Stage 2: Build AF_XDP Fastpath -----
FROM ubuntu:24.04 AS afxdp-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev libelf-dev libxdp-dev \
    linux-headers-generic make gcc pkg-config zlib1g-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY src/af_xdp/ src/af_xdp/
COPY modules/ modules/
COPY Makefile .

# Biên dịch trực tiếp và bắt buộc thành công (không bỏ qua lỗi bằng || echo)
RUN mkdir -p build && \
    clang -O2 -g -I src/af_xdp -I modules/xdp-tools/headers \
    -o build/shield-fastpath \
    src/af_xdp/af_xdp_main.c src/af_xdp/dpi.c \
    -lpthread -lelf -lz -lbpf -lxdp

# ----- Stage 3: Build Go Control Plane -----
FROM golang:1.23-bookworm AS go-builder

WORKDIR /build

# Tối ưu hóa Docker layer caching cho Go dependencies
COPY src/control_plane/go.mod src/control_plane/go.sum ./
RUN go mod download

# Copy source và biên dịch
COPY src/control_plane/ .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /build/shield-ctrl .

# ----- Stage 4: Production Runtime -----
FROM ubuntu:24.04

LABEL maintainer="Shield-Core Team"
LABEL description="Shield-Core XDP Anti-DDoS Protection Platform"

ENV DEBIAN_FRONTEND=noninteractive

# Cài đặt thêm curl phục vụ HEALTHCHECK
RUN apt-get update && apt-get install -y --no-install-recommends \
    libbpf1 libelf1 zlib1g iproute2 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false shield || true

WORKDIR /opt/shield-core

# Copy binaries từ các stage trước
COPY --from=go-builder /build/shield-ctrl build/shield-ctrl
COPY --from=bpf-builder /build/src/bpf/xdp_main.o src/bpf/xdp_main.o
COPY --from=afxdp-builder /build/build/shield-fastpath build/shield-fastpath

# Copy các thư mục cấu hình và web tĩnh
COPY conf/ conf/
COPY data/ data/
COPY scripts/ scripts/
COPY web/ web/

# Tạo thư mục logs và phân quyền
RUN mkdir -p logs && chmod 755 logs && chown -R shield:shield /opt/shield-core

# Mở cổng API HTTPS thực tế (9090)
EXPOSE 9090

# Cấu hình kiểm tra sức khoẻ Container qua HTTPS
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -k -f https://localhost:9090/health || exit 1

ENV SHIELD_IFACE=eth0

ENTRYPOINT ["build/shield-ctrl"]
