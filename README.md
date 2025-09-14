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
$ ./output/app.elf -- uname -a
Linux container 6.1.149-bottlefire #1 SMP Sat Sep  6 13:50:25 UTC 2025 x86_64 GNU/Linux

# show usage
$ ./output/app.elf --help
Bottlefire microVM Image

Usage: app.elf [OPTIONS] [SUBCOMMAND]

Options:
      --cpus <CPUS>              Number of CPU cores
      --memory <MEMORY>          Amount of memory (in MB) allocated to the microVM [default: 256]
      --boot-args <BOOT_ARGS>    Kernel command line [default: "console=ttyS0 reboot=k panic=-1"]
      --entrypoint <ENTRYPOINT>  Container entrypoint
      --                         Separator; everything after goes to the container
      --env <KEY=VALUE>          Container environment variables
      --verbose                  Enable verbose output
      --cwd <CWD>                Container working directory [default: ]
  -p, --publish <HOST:VM>        Publish host:vm port forward (e.g. -p 8080:8080)
  -v, --volume <HOST:VM[:ro]>    Directory/volume mappings (e.g. -v ./data:/data)
  -h, --help                     Print help

Subcommands:
  ssh        Auto-connect to the running microVM via SSH
             Options: -p, --pid <PID>
             Pass-through: arguments after `--` go to ssh(1)
  systemd    Print a systemd service unit and exit
```

## How it works

Depending on whether embedded data is detected and whether running as PID 1, `bake` runs in one of the following modes:

- If PID is 1 and env var `BAKE_NOT_INIT` is not `1`: vminit mode. `bake` assumes that it is running as the init task inside the Firecracker VM, and perform the init sequence.
- If PID is not 1, and embedded data is detected: run mode - accept Firecracker startup parameters (e.g. number of CPUs, memory size, network config), extract kernel and initrd into memfd, start firecracker.
- If PID is not 1, and embedded data is not detected: build mode - accept `--input`, `--firecracker`, `--kernel`, `--initrd`, `--rootfs`, build a binary from `/proc/self/exe` (or the provided input elf) with everything embedded.

### Init sequence (src/vminit.rs)

When running as PID 1 inside the microVM, `bake` executes an init routine that prepares the root filesystem, host-guest connectivity, optional volume mounts, and finally launches the container process with `runc`.

- Bootstrap system mounts and loopback
  - Mount `proc`, `sysfs`, `devtmpfs`, and unified `cgroup2`.
  - Bring `lo` up.

- Parse kernel cmdline and banner
  - Read `/proc/cmdline`, parse `bake.*` parameters and `quiet`.
  - If not quiet, print a banner and `/proc/version` for diagnostics.
  - Fetch BootManifest from host vsock port 13 containing container runtime parameters.

- Expose embedded rootfs via device-mapper
  - Read `bake.rootfs_offset` and `bake.rootfs_size` (sectors) from cmdline.
  - Create a linear mapping `rootfs` with `dmsetup` over `/dev/vda` at the given offset/size.

- Build overlay root on top of ephemeral disk
  - Format `/dev/vdb` as ext4 and mount at `/ephemeral`.
  - Prepare overlay dirs: `/ephemeral/rootfs.overlay/{upper,work}` and `/ephemeral/container-tmp` (mode 1777).
  - Mount the base rootfs from `/dev/mapper/rootfs` at `/rootfs.base`.
  - Mount an overlay at `/rootfs` with `lowerdir=/rootfs.base`, `upperdir=/ephemeral/rootfs.overlay/upper`, `workdir=/ephemeral/rootfs.overlay/work`.

- Set up host-guest networking over vsock with SOCKS5 and tun2socks
  - Inside the VM, start a SOCKS5 server listening on vsock port 10.
  - Start a small TCP proxy that exposes that vsock service on `127.0.0.10:10` for local clients.
  - Create a TUN device `hostnet` (L3), assign `198.18.0.1/32`, bring it up, and add a default route via `hostnet`.
  - Start a UDP bridge that exchanges UDP packets with the host over vsock port 11 (length-prefixed rkyv-encoded frames).
  - Add nftables and `ip rule` entries to policy-route UDP (fwmark `0x64`) via table 100 (via interface `hostudp` created by the UDP injector).
  - Launch `tun2socks` to route TCP over the local SOCKS5 proxy (`socks5://127.0.0.10:10`), keeping the VM’s loopback as the outgoing interface.

- Mount shared volumes via 9p over vsock (optional)
  - If volumes are specified in the BootManifest, start a per-volume Unix-to-vsock proxy that connects to host vsock port 12 and first writes the length-prefixed guest path.
  - Mount each volume into the overlay root under `/rootfs<guest_path>` using `9p` with `trans=unix,version=9p2000.L` pointing at the per-volume UDS.

- Launch the container with runc
  - Read container runtime params from BootManifest:
    - entrypoint, args, env variables, and working directory.
  - Create a container bundle at `/var/lib/container` and generate `config.json` (OCI runtime spec):
    - Root at `/rootfs` (overlay), terminal enabled, UID/GID 0, wide capabilities enabled.
    - Namespaces: `pid`, `ipc`, `uts`, `mount`.
    - Mounts: `proc`, `sys` (ro), `cgroup` (ro), `dev` (tmpfs) + `devpts`, bind `/etc/resolv.conf`, bind `/ephemeral/container-tmp` to `/tmp`.
    - PATH is set; `env`/`cwd` applied if specified.
  - Execute `runc run --no-pivot container1` in the bundle directory with stdio attached.

- Shutdown
  - On container exit, log status (if non-zero) and trigger a reboot via `/proc/sysrq-trigger` (`b`).

### Host-side flow (run mode)

When invoked on the host with embedded resources present, `bake` prepares resources, sets up vsock-backed host services, and launches Firecracker:

- Embedded data and params
  - Locate embedded archive and rootfs trailer via the magic footer; deserialize metadata (firecracker, kernel, initrd, rootfs size, optional entrypoint/args/env/cwd).
  - Merge CLI overrides with embedded values and BAKE_VM_ environment variables.
  - Create a BootManifest containing entrypoint, args, env, cwd, and volumes, served to the VM over vsock port 13.
  - Compute and pass `bake.rootfs_offset` and `bake.rootfs_size` (in 512-byte sectors) so the guest can expose the rootfs from the host ELF.

- Transient workspace and cleanup
  - Create a temp dir for Firecracker artifacts and UDS endpoints; install signal and panic hooks to remove it on exit.

- Vsock endpoints for guest services
  - Start Unix-socket services that Firecracker's vsock backend connects to per guest port:
    - Port 10: SOCKS5 TCP proxy (for guest outbound TCP).
    - Port 11: UDP bridge/injector (guest<->host UDP via framed rkyv messages).
    - Port 12: 9p file server (guest volume mounts).
    - Port 13: BootManifest server (provides container runtime parameters to VM).
  - If `-v/--volume` is provided, start the 9p server and include volume mount points in the BootManifest.

- Host TCP port forwards (`-p/--publish`)
  - For each `HOST:VM` mapping, bind a host TCP listener and, on accept, open a vsock connection (via the Firecracker UDS) to guest port 10, perform a SOCKS5 CONNECT to `127.0.0.1:VM`, and pipe data bidirectionally.

- Memfd resources and drives
  - Copy firecracker, kernel, and initrd bytes into sealed `memfd`s (no CLOEXEC) and reference them by `/proc/self/fd/<n>` paths.
  - Point Firecracker root drive at our own executable FD (read-only) so the guest can slice out the embedded rootfs; create a 2GiB ephemeral ext4 disk file (read-write) for overlay upper/work/tmp.

- Firecracker launch
  - Generate a minimal config (boot source, two drives, vsock with `guest_cid=3`, no network interfaces, machine config for vCPUs/mem). Honor `--verbose` by adjusting log level.
  - Write the config to a `memfd`, then exec Firecracker with `--config-file <fd> --no-api --enable-pci`; set `PR_SET_PDEATHSIG=SIGKILL` to ensure teardown with the parent.
  - If `BAKE_DRY_RUN=1`, print the config JSON and exit instead of launching.

### SSH helper

When a microVM is running, `bake` exposes two `memfd` FDs from the host process:

- `memfd:ssh_proxy_path`: contains the Unix socket path for the host-side SSH proxy.
- `memfd:id_ecdsa`: contains the private key used by the guest SSH server.

To simplify connecting, `app.elf ssh` auto-discovers a running instance of the same binary, and then `exec`s `ssh` with the correct `ProxyCommand` and identity key:

```bash
$ ./output/app.elf ssh

# Or target a specific PID if multiple are running
$ ./output/app.elf ssh --pid 1260276

# Pass arbitrary ssh options after `--`
$ ./output/app.elf ssh -- -L 8080:localhost:8080 -o ConnectTimeout=5
```

If multiple instances are running, it prints their PIDs and exits so you can stop the others and retry.
