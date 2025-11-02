#!/bin/bash

set -e

cd "$(dirname $0)/.."

arch="$(uname -m)"
if [ "$arch" = "x86_64" ]; then
  arch=amd64
elif [ "$arch" = "aarch64" ]; then
  arch=arm64
else
  echo "unsupported arch: $arch"
  exit 1
fi

if [ "$TARGETARCH" = "amd64" ]; then
  echo -n ""
elif [ "$TARGETARCH" = "arm64" ]; then
  echo -n ""
else
  echo "Invalid TARGETARCH" >&2
  exit 1
fi

container_id=$(docker create --platform "linux/$TARGETARCH" "debian:trixie")
tempfile=$(mktemp -t debian-bake-XXXXXXXX)
rm -f "$tempfile"
docker export $container_id | sqfstar "$tempfile"
docker rm $container_id

./bake.$arch.elf --cpus 1 -v ./output:/output -v "$tempfile":/rootfs.img:ro -- \
  --input /opt/bake/bake.$TARGETARCH \
  --firecracker /opt/bake/firecracker.$TARGETARCH \
  --kernel /opt/bake/kernel.$TARGETARCH \
  --initrd /opt/bake/initrd.$TARGETARCH.img \
  --output /output/debian.$TARGETARCH.elf --rootfs /rootfs.img

rm -f "$tempfile"
