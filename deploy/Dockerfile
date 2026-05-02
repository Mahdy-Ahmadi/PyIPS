FROM rust:1.75-bookworm AS builder

WORKDIR /build

# Build Rust core
COPY rust-core/ ./rust-core/
WORKDIR /build/rust-core
RUN cargo build --release

FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    libbpf-dev \
    clang \
    llvm \
    bpftool \
    iptables \
    nftables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Rust built library
COPY --from=builder /build/rust-core/target/release/libpyips_core.so /usr/local/lib/
COPY --from=builder /build/rust-core/target/release/pyips_core.so /app/

# Copy Python control plane
COPY python-control/ ./python-control/
COPY config/ ./config/

ENV PYTHONPATH=/app/python-control
ENV LD_LIBRARY_PATH=/usr/local/lib

RUN pip install --no-cache-dir -r python-control/requirements.txt

EXPOSE 8000 8080

CMD ["python", "-m", "uvicorn", "pyips_pro.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
