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

container_id="$(docker create bake)"
tempdir="$(mktemp -d -t bake-selfpack-XXXXXXXX)"
docker export "$container_id" | sqfstar "$tempdir/rootfs.img"

target=arm64
docker run -it --rm -v "$tempdir:/data" -v "$PWD:/host:ro" \
    --entrypoint /opt/bake/bake.$arch \
    bake \
    --input /host/bake.macos.bin \
    --firecracker /opt/bake/firecracker.$target \
    --kernel /opt/bake/kernel.$target \
    --initrd /opt/bake/initrd.$target.img \
    --rootfs /data/rootfs.img \
    --entrypoint /opt/bake/bake.$target \
    --env BAKE_NOT_INIT=1 \
    --env BAKE_BUILD_FIRECRACKER=/opt/bake/firecracker.$target \
    --env BAKE_BUILD_KERNEL=/opt/bake/kernel.$target \
    --env BAKE_BUILD_INITRD=/opt/bake/initrd.$target.img \
    --output /data/app.macos.bin

cp "$tempdir/app.macos.bin" ./bake-selfpack.macos.bin
rm -rf "$tempdir"
