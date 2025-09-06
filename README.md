# bake

`bake` is a Linux CLI tool that can embed microVM resources (firecracker binary, kernel, initrd, boot disk) into itself. It also implements bidirectional communication between VM and host - including networking and directory sharing - entirely in userspace, without requiring root privilege.

## Usage

The Docker image includes pre-packaged `bake`, firecracker, kernel and initrd binaries for amd64 and arm64 platforms.

```bash
# make sure `./rootfs.squashfs.img` exists
# create output directory
$ mkdir -p output

# assuming you are building on an amd64 host for an amd64 target
$ docker run -it --rm \
  -v ./rootfs.squashfs.img:/rootfs.img:ro \
  -v ./output:/output \
  --entrypoint /opt/bake/bake.amd64 \
  ghcr.io/losfair/bake \
  --input /opt/bake/bake.amd64 \
  --firecracker /opt/bake/firecracker.amd64 \
  --kernel /opt/bake/kernel.amd64 \
  --initrd /opt/bake/initrd.amd64.img \
  --rootfs /rootfs.img \
  --output /output/app.elf

# start microVM and print uname
$ ./output/app.elf --arg=uname --arg=-a
Linux container 6.1.149-bottlefire #1 SMP Sat Sep  6 13:50:25 UTC 2025 x86_64 GNU/Linux

# show usage
$ ./output/app.elf --help
Bottlefire microVM Image

Usage: app.elf [OPTIONS]

Options:
      --cpus <CPUS>              Number of CPU cores
      --memory <MEMORY>          Amount of memory (in MB) allocated to the microVM [default: 256]
      --boot-args <BOOT_ARGS>    Kernel command line [default: "console=ttyS0 reboot=k panic=-1"]
      --entrypoint <ENTRYPOINT>  Container entrypoint
      --arg <ARG>                Container arguments
      --env <KEY=VALUE>          Container environment variables
      --verbose                  Enable verbose output
      --cwd <CWD>                Container working directory [default: ]
  -p, --publish <HOST:VM>        Publish host:vm port forward (e.g. -p 8080:8080)
  -v, --volume <HOST:VM[:ro]>    Directory/volume mappings (e.g. -v ./data:/data)
  -h, --help                     Print help
```

## How it works

Depending on whether embedded data is detected and whether running as PID 1, `bake` runs in one of the following modes:

- If PID is 1 and env var `BAKE_NOT_INIT` is not `1`: vminit mode. `bake` assumes that it is running as the init task inside the Firecracker VM, and perform the init sequence.
- If PID is not 1, and embedded data is detected: run mode - accept Firecracker startup parameters (e.g. number of CPUs, memory size, network config), extract kernel and initrd into memfd, start firecracker.
- If PID is not 1, and embedded data is not detected: build mode - accept `--input`, `--firecracker`, `--kernel`, `--initrd`, `--rootfs`, build a binary from `/proc/self/exe` (or the provided input elf) with everything embedded.

### Init sequence (src/vminit.rs)

TODO
