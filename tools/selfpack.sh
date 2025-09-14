#!/bin/bash

set -e

cd "$(dirname $0)/.."
./tools/build.sh

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

for target in amd64 arm64; do
  docker run -it --rm -v "$tempdir:/data" \
    --entrypoint /opt/bake/bake.$arch \
    bake \
    --input /opt/bake/bake.$target \
    --firecracker /opt/bake/firecracker.$target \
    --kernel /opt/bake/kernel.$target \
    --initrd /opt/bake/initrd.$target.img \
    --rootfs /data/rootfs.img \
    --entrypoint /opt/bake/bake.$target \
    --env BAKE_NOT_INIT=1 \
    --env BAKE_BUILD_FIRECRACKER=/opt/bake/firecracker.$target \
    --env BAKE_BUILD_KERNEL=/opt/bake/kernel.$target \
    --env BAKE_BUILD_INITRD=/opt/bake/initrd.$target.img \
    --output /data/app.$target.elf
done

cp "$tempdir/app.amd64.elf" ./bake.amd64.elf
cp "$tempdir/app.arm64.elf" ./bake.arm64.elf
rm -rf "$tempdir"
