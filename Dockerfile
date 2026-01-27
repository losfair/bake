FROM rust:1.89-slim-bullseye AS build_bake
RUN apt-get update && apt-get install -o Acquire::Retries="5" -y musl-tools python3-pip && python3 -m pip install cargo-zigbuild
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
WORKDIR /build
COPY Cargo.toml Cargo.lock /build/bake/
COPY ./src/ /build/bake/src/
COPY ./rust-p9/ /build/bake/rust-p9/
RUN cd /build/bake && cargo zigbuild --release --target x86_64-unknown-linux-musl && \
  cargo zigbuild --release --target aarch64-unknown-linux-musl && \
  mkdir ../bin && \
  cp target/x86_64-unknown-linux-musl/release/bake ../bin/bake.amd64 && \
  cp target/aarch64-unknown-linux-musl/release/bake ../bin/bake.arm64

FROM golang:1.25-alpine AS build_tun2socks
WORKDIR /opt
RUN apk add git
RUN mkdir tun2socks && cd tun2socks && git init && \
  git remote add origin https://github.com/xjasonlyu/tun2socks && \
  git fetch --depth 1 origin a1a64030c4c08b1970736e6dca5dbf070535407a && \
  git checkout FETCH_HEAD
RUN cd tun2socks && \
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o /opt/tun2socks.amd64 . && \
  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w" -o /opt/tun2socks.arm64 .

FROM debian:bullseye-slim AS build_vm_initrd_amd64
RUN apt-get update && apt-get install -y curl cpio
WORKDIR /build
RUN curl -fsSL -o alpine.tar.gz https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-minirootfs-3.22.1-x86_64.tar.gz
RUN mkdir rootfs && cd rootfs && tar xzf ../alpine.tar.gz && cat /etc/resolv.conf > etc/resolv.conf && \
  LD_LIBRARY_PATH=$(pwd)/lib:$(pwd)/usr/lib ./lib/ld-musl-x86_64.so.1 ./sbin/apk add --root . --no-scripts \
    runc device-mapper iproute2 nftables e2fsprogs openssh wireguard-tools
COPY --from=build_bake /build/bin/bake.amd64 ./rootfs/init
COPY --from=build_tun2socks /opt/tun2socks.amd64 ./rootfs/usr/bin/tun2socks
RUN cd rootfs && bash -c "set -euo pipefail; find . | cpio -o --format=newc | gzip > /build/initrd.cpio.gz"

FROM debian:bullseye-slim AS build_vm_initrd_arm64
RUN apt-get update && apt-get install -y curl cpio
WORKDIR /build
RUN curl -fsSL -o alpine.tar.gz https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.1-aarch64.tar.gz
RUN mkdir rootfs && cd rootfs && tar xzf ../alpine.tar.gz && cat /etc/resolv.conf > etc/resolv.conf && \
  LD_LIBRARY_PATH=$(pwd)/lib:$(pwd)/usr/lib ./lib/ld-musl-aarch64.so.1 ./sbin/apk add --root . --no-scripts \
    runc device-mapper iproute2 nftables e2fsprogs openssh wireguard-tools
COPY --from=build_bake /build/bin/bake.arm64 ./rootfs/init
COPY --from=build_tun2socks /opt/tun2socks.arm64 ./rootfs/usr/bin/tun2socks
RUN cd rootfs && bash -c "set -euo pipefail; find . | cpio -o --format=newc | gzip > /build/initrd.cpio.gz"

FROM debian:bookworm-slim AS build_kernel_base
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    bc \
    bison \
    flex \
    libssl-dev \
    libelf-dev \
    dwarves \
    curl \
    xz-utils \
    ca-certificates \
    python3 \
    clang \
    lld \
    llvm \
    pkg-config \
    rsync \
    file && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build/linux
RUN curl -fsSL -o linux.tar.xz https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.149.tar.xz && \
    tar -xJf linux.tar.xz --strip-components=1 && rm linux.tar.xz

COPY ./kernel_config/microvm-kernel-ci-x86_64-6.1.config /tmp/config.x86_64
COPY ./kernel_config/microvm-kernel-ci-aarch64-6.1.config /tmp/config.aarch64

FROM build_kernel_base AS build_kernel_amd64
WORKDIR /build/linux
RUN make mrproper && \
    cp /tmp/config.x86_64 .config && \
    make LLVM=1 ARCH=x86_64 olddefconfig && \
    make LLVM=1 ARCH=x86_64 -j"$(nproc)" vmlinux && \
    mkdir -p /opt && cp vmlinux /opt/kernel.amd64

FROM build_kernel_base AS build_kernel_arm64
WORKDIR /build/linux
RUN make mrproper && \
    cp /tmp/config.aarch64 .config && \
    make LLVM=1 ARCH=arm64 olddefconfig && \
    make LLVM=1 ARCH=arm64 -j"$(nproc)" Image && \
    mkdir -p /opt && cp arch/arm64/boot/Image /opt/kernel.arm64

FROM debian:bullseye-slim AS fetch_firecracker
RUN apt-get update && apt-get install -y curl
WORKDIR /opt
RUN curl -fsSL -o firecracker-v1.13.1-x86_64.tgz https://github.com/firecracker-microvm/firecracker/releases/download/v1.13.1/firecracker-v1.13.1-x86_64.tgz && \
  curl -fsSL -o firecracker-v1.13.1-aarch64.tgz https://github.com/firecracker-microvm/firecracker/releases/download/v1.13.1/firecracker-v1.13.1-aarch64.tgz && \
  tar xzf firecracker-v1.13.1-x86_64.tgz --no-same-owner && \
  tar xzf firecracker-v1.13.1-aarch64.tgz --no-same-owner && \
  mv release-v1.13.1-x86_64/firecracker-v1.13.1-x86_64 ./firecracker.amd64 && \
  mv release-v1.13.1-aarch64/firecracker-v1.13.1-aarch64 ./firecracker.arm64

# We are doing kinda strange thing here -
# this image is ALWAYS built for amd64, regardless of the current platform architecture.
FROM --platform=linux/amd64 debian:bullseye-slim AS bake
RUN apt-get update && apt-get install -y --no-install-recommends \
    squashfs-tools \
    erofs-utils \
    ca-certificates makefs && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /opt/bake
COPY --from=build_kernel_amd64 /opt/kernel.amd64 ./kernel.amd64
COPY --from=build_kernel_arm64 /opt/kernel.arm64 ./kernel.arm64
COPY --from=fetch_firecracker /opt/firecracker.amd64 /opt/firecracker.arm64 ./
COPY --from=build_bake /build/bin/ /opt/bake/
COPY --from=build_vm_initrd_amd64 /build/initrd.cpio.gz ./initrd.amd64.img
COPY --from=build_vm_initrd_arm64 /build/initrd.cpio.gz ./initrd.arm64.img
ENV BAKE_NOT_INIT=1
