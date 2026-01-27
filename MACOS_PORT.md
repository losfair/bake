# macOS Port Plan: Virtualization.framework Support for Bake

This document outlines the plan to add macOS support for `bake` using Apple's Virtualization.framework as the hypervisor backend, replacing Firecracker which is Linux-only.

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current Architecture Analysis](#current-architecture-analysis)
3. [Target Architecture](#target-architecture)
4. [Platform Abstraction Layer](#platform-abstraction-layer)
5. [Component Migration Strategy](#component-migration-strategy)
6. [Implementation Phases](#implementation-phases)
7. [Technical Challenges & Mitigations](#technical-challenges--mitigations)
8. [Testing Strategy](#testing-strategy)
9. [Dependencies & Tooling](#dependencies--tooling)
10. [References](#references)

---

## Executive Summary

**Goal**: Enable `bake` to run on macOS by implementing a Virtualization.framework backend while maintaining full feature parity with the Linux/Firecracker implementation.

**Approach**: Create a platform abstraction layer (`Hypervisor` trait) that abstracts the differences between Firecracker and Virtualization.framework, allowing the core bake logic to remain platform-agnostic.

**Key Changes**:

- Replace Firecracker with Virtualization.framework on macOS
- Replace `memfd_create()` with temporary files or memory-mapped files
- Replace device-mapper with direct disk image attachment
- Adapt networking to use Virtualization.framework's VirtIO interfaces
- Port or replace Linux-specific syscalls with macOS equivalents

---

## Current Architecture Analysis

### Hypervisor: Firecracker

Bake currently uses **Firecracker v1.13.1**, configured via JSON with:

- Boot source (kernel, initrd, boot args)
- Two block devices: read-only rootfs + read-write ephemeral ext4
- Vsock device (CID=3) for all host-guest communication
- No traditional network interfaces (all networking via vsock proxies)

### Key Linux-Specific Components

| Component           | Linux Implementation        | macOS Equivalent                            |
| ------------------- | --------------------------- | ------------------------------------------- |
| Hypervisor          | Firecracker + KVM           | Virtualization.framework                    |
| Memory-backed files | `memfd_create()` + sealing  | Temporary files or `mmap()`                 |
| Rootfs mapping      | device-mapper linear target | Direct disk image attachment                |
| Networking          | vsock + nftables + TUN      | VZVirtioSocketDevice + native networking    |
| 9P filesystem       | Custom 9P server over vsock | VZVirtioFileSystemDeviceConfiguration       |
| Process lifecycle   | `PR_SET_PDEATHSIG`          | `kqueue` + process groups                   |
| PTY handling        | `openpty()` + `login_tty()` | Same (POSIX compatible)                     |
| Container runtime   | runc                        | runc (works on macOS via Lima-style setups) |

### Communication Architecture (vsock ports)

| Port | Purpose                |
| ---- | ---------------------- |
| 10   | SOCKS5 TCP proxy       |
| 11   | UDP bridge             |
| 12   | 9P file server         |
| 13   | Boot manifest delivery |
| 14   | Console PTY bridge     |
| 22   | SSH (sshd in guest)    |

This vsock-based architecture is **directly portable** to Virtualization.framework since it also provides VirtIO socket support via `VZVirtioSocketDevice`.

---

## Target Architecture

### macOS Hypervisor Stack

```
┌─────────────────────────────────────────────────────────┐
│                    bake (Rust)                          │
├─────────────────────────────────────────────────────────┤
│              Platform Abstraction Layer                 │
│         ┌─────────────────┬─────────────────┐          │
│         │  FirecrackerVM  │  VirtualizationVM│          │
│         │    (Linux)      │    (macOS)       │          │
│         └────────┬────────┴────────┬────────┘          │
│                  │                 │                    │
│         ┌────────▼────────┐ ┌──────▼───────┐           │
│         │   Firecracker   │ │ Virtualization│           │
│         │   + KVM         │ │  .framework   │           │
│         └─────────────────┘ └──────────────┘           │
└─────────────────────────────────────────────────────────┘
```

### Virtualization.framework Configuration

```swift
// Conceptual configuration (will be accessed via Rust FFI)
VZVirtualMachineConfiguration:
  ├── bootLoader: VZLinuxBootLoader
  │     ├── kernelURL: embedded kernel
  │     ├── initialRamdiskURL: embedded initrd
  │     └── commandLine: boot args
  ├── cpuCount: N
  ├── memorySize: M bytes
  ├── storageDevices:
  │     ├── VZVirtioBlockDeviceConfiguration (rootfs, read-only)
  │     └── VZVirtioBlockDeviceConfiguration (ephemeral, read-write)
  ├── socketDevices:
  │     └── VZVirtioSocketDeviceConfiguration
  ├── serialPorts:
  │     └── VZVirtioConsoleDeviceSerialPortConfiguration
  └── directorySharingDevices:
        └── VZVirtioFileSystemDeviceConfiguration (for volumes)
```

---

## Platform Abstraction Layer

### Core Trait Design

```rust
// src/hypervisor/mod.rs

/// Platform-agnostic hypervisor interface
#[async_trait]
pub trait Hypervisor: Send + Sync {
    /// Create a new VM with the given configuration
    async fn create(config: VmConfig) -> Result<Self>
    where
        Self: Sized;

    /// Start the virtual machine
    async fn start(&mut self) -> Result<()>;

    /// Stop the virtual machine
    async fn stop(&mut self) -> Result<()>;

    /// Get a vsock connection to the guest
    async fn connect_vsock(&self, port: u32) -> Result<VsockStream>;

    /// Listen for vsock connections from the guest
    async fn listen_vsock(&self, port: u32) -> Result<VsockListener>;

    /// Get the VM's current state
    fn state(&self) -> VmState;
}
```

**Design note**: The above trait is **not object-safe** because `create` returns `Self`. That is fine if the build selects the implementation at compile time (per target OS). If you want to hold `Box<dyn Hypervisor>`, move construction into a factory function (e.g., `PlatformVm::create(...)`) and keep the trait object-safe.

/// VM configuration (platform-agnostic)
pub struct VmConfig {
pub kernel: ResourceHandle, // Kernel image
pub initrd: ResourceHandle, // Initial ramdisk
pub rootfs: ResourceHandle, // Root filesystem
pub boot_args: String, // Kernel command line
pub cpus: u32, // Number of vCPUs
pub memory_mb: u64, // Memory in MiB
pub ephemeral_disk_mb: u64, // Ephemeral disk size
pub socket_path: PathBuf, // Unix socket directory
}

/// Handle to an embedded or file-based resource
pub enum ResourceHandle {
Embedded { offset: u64, size: u64 },
File(PathBuf),
Memory(Vec<u8>),
}

```

### Module Structure

```

src/
├── hypervisor/
│ ├── mod.rs # Trait definitions, VmConfig
│ ├── firecracker.rs # Linux implementation (refactored from current)
│ └── virtualization.rs # macOS implementation
├── platform/
│ ├── mod.rs # Platform detection, feature flags
│ ├── linux.rs # Linux-specific utilities
│ └── macos.rs # macOS-specific utilities
└── ... (existing modules)

````

### Conditional Compilation

```rust
// src/hypervisor/mod.rs

#[cfg(target_os = "linux")]
mod firecracker;
#[cfg(target_os = "linux")]
pub use firecracker::FirecrackerVm as PlatformVm;

#[cfg(target_os = "macos")]
mod virtualization;
#[cfg(target_os = "macos")]
pub use virtualization::VirtualizationVm as PlatformVm;
````

---

## Component Migration Strategy

### 1. Hypervisor Layer

| Aspect             | Linux (Firecracker)               | macOS (Virtualization.framework)    |
| ------------------ | --------------------------------- | ----------------------------------- |
| Boot loader        | Kernel + initrd passed via config | `VZLinuxBootLoader`                 |
| Block devices      | JSON drive config                 | `VZVirtioBlockDeviceConfiguration`  |
| Vsock              | `vsock` crate with CID=3          | `VZVirtioSocketDevice` + native API |
| Process management | Fork + exec firecracker binary    | In-process via FFI                  |

**Implementation**: Implement custom bindings to Virtualization.framework via the `objc2` crate. `virtualization-rs` is currently too early-stage for the APIs/features we need (vsock listen/connect, VM lifecycle control, and device configuration coverage), so we treat it as a reference rather than a dependency.

### 2. Memory-Backed Files (`memfd_create`)

**Current use**: Store embedded kernel/initrd/rootfs in sealed memory files, pass to Firecracker via `/dev/fd/N`.

**macOS approach**:

```rust
#[cfg(target_os = "macos")]
fn create_temp_resource(data: &[u8], name: &str) -> Result<(tempfile::TempDir, PathBuf)> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(name);
    std::fs::write(&path, data)?;
    Ok((dir, path))
}
```

**Important**: keep the `TempDir` alive for the **lifetime of the VM** (store it on the VM struct). Otherwise the file is deleted early.

Alternatively, use memory-mapped files with `mmap()` for zero-copy access.

### 3. Rootfs Handling

**Current**: Embedded in ELF binary, exposed via device-mapper linear target in guest.

**macOS approach**:

- Extract rootfs to temporary file at runtime
- Attach as `VZDiskImageStorageDeviceAttachment` (read-only)
- Guest sees it as `/dev/vda` (same as current)

### 4. Ephemeral Disk

**Current**: Created via `fallocate()` + `mkfs.ext4`, attached as second drive.

**macOS approach**:

- Create a sparse file in Rust (no shell dependency) and let the guest format it as ext4:
    - `std::fs::OpenOptions` + `set_len()` to desired size
    - Attach via `VZDiskImageStorageDeviceAttachment` (read-write)
- Formatting still happens inside the guest as today.

### 5. Vsock Communication

**Excellent news**: Virtualization.framework provides `VZVirtioSocketDevice` with the same semantics as Linux vsock.

```rust
#[cfg(target_os = "macos")]
impl Hypervisor for VirtualizationVm {
    async fn connect_vsock(&self, port: u32) -> Result<VsockStream> {
        // Use VZVirtioSocketDevice.connect(toPort:) via FFI
        let connection = self.socket_device.connect(port)?;
        Ok(VsockStream::from_vz_connection(connection))
    }
}
```

**Implementation note**: The Linux `vsock` crate is not available on macOS. Create a small platform-agnostic `VsockStream/VsockListener` wrapper with a macOS backend that maps `VZVirtioSocketDevice` connect/listen APIs to async streams.

**Port mapping remains identical**:

- Port 10: SOCKS5 TCP proxy
- Port 11: UDP bridge
- Port 12: 9P file server
- Port 13: Boot manifest
- Port 14: Console
- Port 22: SSH

### 6. File Sharing (9P → VirtioFS)

**Option A**: Keep current 9P implementation over vsock (works unchanged)

**Option B**: Use native `VZVirtioFileSystemDeviceConfiguration` which provides better performance:

```swift
let share = VZSharedDirectory(url: hostURL, readOnly: false)
let config = VZVirtioFileSystemDeviceConfiguration(tag: "hostshare")
config.share = VZSingleDirectoryShare(directory: share)
```

Guest mounts via: `mount -t virtiofs hostshare /mnt/share`

**Recommendation**: Implement Option B for better performance, with Option A as fallback.

**Kernel requirement**: VirtioFS requires `CONFIG_VIRTIO_FS=y` (and the appropriate FUSE/virtio modules) in the guest kernel.

### 7. Networking

**Current architecture** (vsock-based) ports directly:

- SOCKS5 proxy on host → guest connects via vsock port 10
- UDP bridge over vsock port 11
- TUN device in guest (`hostnet`) routes through SOCKS5

**No changes needed** for basic networking since it's all vsock-based.

**Enhancement opportunity**: Virtualization.framework offers `VZNATNetworkDeviceAttachment` for simpler NAT networking:

```swift
let network = VZVirtioNetworkDeviceConfiguration()
network.attachment = VZNATNetworkDeviceAttachment()
```

This could simplify networking but would require guest-side changes.

### 8. Console/Terminal

**Current**: PTY via vsock port 14, using `openpty()` + `login_tty()`.

**macOS approach**: `openpty()` and PTY handling are POSIX-compatible on macOS. The vsock-based console bridge works unchanged.

**Alternative**: Use `VZVirtioConsoleDeviceSerialPortConfiguration` for native console:

```swift
let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
serial.attachment = VZFileHandleSerialPortAttachment(
    fileHandleForReading: readHandle,
    fileHandleForWriting: writeHandle
)
```

### 9. Process Lifecycle

**Current**: `PR_SET_PDEATHSIG` ensures Firecracker dies when parent exits.

**macOS approach**:

```rust
#[cfg(target_os = "macos")]
fn setup_child_termination() -> Result<()> {
    // Use kqueue to monitor parent process
    // Or use process groups with SIGTERM forwarding
    unsafe {
        libc::setpgid(0, 0);
    }
    // Register signal handler to forward SIGTERM to VM
}
```

For in-process Virtualization.framework, this is less critical since the VM runs in the same process.

---

## Implementation Phases

### Phase 1: Platform Abstraction (Foundation)

**Duration estimate**: N/A (first milestone)

**Tasks**:

1. Create `src/hypervisor/mod.rs` with `Hypervisor` trait
2. Create `src/platform/mod.rs` for platform utilities
3. Refactor `src/firecracker.rs` into `src/hypervisor/firecracker.rs`
4. Abstract `memfd_create` usage into platform module
5. Create feature flags in `Cargo.toml`:
    ```toml
    [features]
    default = []
    macos = ["virtualization-rs", "objc2"]
    linux = ["vsock", "nix"]
    ```

**Deliverable**: Existing Linux functionality works with new abstraction layer.

### Phase 2: Basic macOS VM (Proof of Concept)

**Tasks**:

1. Implement minimal Virtualization.framework bindings with `objc2` (VM lifecycle + Linux boot loader + block devices + vsock + console)
2. Implement `VirtualizationVm` struct with basic lifecycle
3. Implement kernel/initrd/rootfs loading from files
4. Implement vsock connection via `VZVirtioSocketDevice`
5. Boot a minimal Linux VM on macOS

**Deliverable**: `bake` can boot a VM on macOS with console output.

### Phase 3: Full Communication Stack

**Tasks**:

1. Port SOCKS5 proxy to use platform-agnostic vsock
2. Port UDP bridge
3. Port 9P file server (or implement VirtioFS alternative)
4. Port boot manifest server
5. Port console bridge
6. Test SSH functionality

**Deliverable**: Full host-guest communication on macOS.

### Phase 4: Binary Embedding

**Tasks**:

1. Adapt ELF embedding for Mach-O binaries (or keep ELF with shim)
2. Implement resource extraction on macOS
3. Handle code signing requirements
4. Test self-contained binary execution

**Deliverable**: Self-contained bake binaries work on macOS.

### Phase 5: Feature Parity & Polish

**Tasks**:

1. Volume mounting with full flag support
2. Port forwarding
3. WireGuard support (if applicable on macOS)
4. Network allowlist
5. Systemd unit generation (macOS launchd equivalent)
6. Error handling and user-friendly messages

**Deliverable**: Full feature parity with Linux version.

### Phase 6: Build System & CI

**Tasks**:

1. Cross-compilation setup for macOS targets
2. GitHub Actions workflow for macOS builds
3. Integration tests on macOS runners
4. Documentation updates
5. Release automation for universal binaries

**Deliverable**: Automated macOS builds in CI.

---

## Technical Challenges & Mitigations

### Challenge 1: Rust Bindings for Virtualization.framework

**Issue**: The `virtualization-rs` crate is early-stage and does not currently provide enough coverage for Bake's needs.

**Mitigations**:

1. Implement custom bindings using `objc2` (planned approach)
2. Reference the mature Go implementation (`Code-Hex/vz`) for API patterns
3. Optionally contribute missing pieces upstream later, but do not block Bake on `virtualization-rs`

### Challenge 2: Binary Format (ELF vs Mach-O)

**Issue**: Current embedding uses ELF format. macOS uses Mach-O.

**Options**:

1. **Keep ELF**: Ship a thin Mach-O wrapper that extracts and runs the ELF payload
2. **Dual format**: Generate both ELF and Mach-O binaries
3. **Mach-O embedding**: Adapt embedding to use Mach-O sections (`__DATA` segment)

**Recommendation**: Option 3 for native feel, with resource extraction at runtime.

### Challenge 3: Code Signing & Entitlements

**Issue**: Virtualization.framework requires specific entitlements.

**Required entitlement**:

```xml
<key>com.apple.security.virtualization</key>
<true/>
```

**Mitigation**:

- Document signing requirements
- Provide signing scripts for developers
- Consider notarization for distribution

### Challenge 4: Guest Kernel Compatibility

**Issue**: Need Linux kernel with VirtIO drivers for Virtualization.framework.

**Requirements**:

- `CONFIG_VIRTIO_PCI=y`
- `CONFIG_VIRTIO_BLK=y`
- `CONFIG_VIRTIO_NET=y` (optional)
- `CONFIG_VIRTIO_CONSOLE=y`
- `CONFIG_VSOCK=y`
- `CONFIG_VIRTIO_VSOCKETS=y`

**Mitigation**: Current kernel configs in `kernel_config/` likely already include these. Verify and update if needed.

### Challenge 5: No Device-Mapper on macOS

**Issue**: Can't use `dmsetup` to expose embedded rootfs.

**Solution**:

- Extract rootfs to temp file before VM boot
- Pass as `VZDiskImageStorageDeviceAttachment`
- Guest init detects platform and mounts `/dev/vda` directly

### Challenge 6: Container Runtime in Guest

**Clarification**: runc is Linux-specific, but it runs **inside the Linux guest**, not on the macOS host.

**Solution**: This is not an issue since the guest OS remains Linux. Only the host hypervisor changes; runc continues to run inside the VM.

---

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    #[test]
    #[cfg(target_os = "macos")]
    fn test_virtualization_config() {
        // Test VZVirtualMachineConfiguration creation
    }

    #[test]
    fn test_vsock_abstraction() {
        // Test platform-agnostic vsock wrapper
    }
}
```

### Integration Tests

1. **Boot test**: VM boots and reaches init
2. **Console test**: Can interact via vsock console
3. **Network test**: Outbound TCP/UDP connectivity
4. **Volume test**: 9P/VirtioFS mounting works
5. **SSH test**: Can SSH into running VM
6. **Embedding test**: Self-contained binary works

### CI Matrix

```yaml
jobs:
    test:
        strategy:
            matrix:
                os: [ubuntu-latest, macos-latest]
                arch: [x86_64, aarch64]
        runs-on: ${{ matrix.os }}
```

---

## Dependencies & Tooling

### New Rust Dependencies

```toml
[target.'cfg(target_os = "macos")'.dependencies]
objc2 = "0.5"              # Custom Virtualization.framework bindings
core-foundation = "0.9"    # macOS framework utilities
```

### Build Requirements

**macOS**:

- Xcode Command Line Tools
- macOS 11.0+ (Big Sur) for Virtualization.framework
- Code signing certificate (for entitlements)

**Cross-compilation**:

- For x86_64-apple-darwin: Standard Rust target
- For aarch64-apple-darwin: Standard Rust target
- Universal binaries via `lipo`

### Development Setup

```bash
# Install Rust targets
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

# Build for macOS
cargo build --target aarch64-apple-darwin --features macos

# Sign with entitlements
codesign --entitlements entitlements.plist --sign - target/release/bake
```

---

## References

### Apple Documentation

- [Virtualization Framework](https://developer.apple.com/documentation/virtualization)
- [VZVirtualMachine](https://developer.apple.com/documentation/virtualization/vzvirtualmachine)
- [VZLinuxBootLoader](https://developer.apple.com/documentation/virtualization/vzlinuxbootloader)
- [Running Linux in a Virtual Machine](https://developer.apple.com/documentation/virtualization/running_linux_in_a_virtual_machine_on_a_mac)

### Related Projects

- [virtualization-rs](https://github.com/suzusuzu/virtualization-rs) - Rust bindings for Virtualization.framework
- [Code-Hex/vz](https://github.com/Code-Hex/vz) - Go bindings (mature, good reference)
- [Lima](https://github.com/lima-vm/lima) - Linux VMs on macOS using Virtualization.framework
- [Tart](https://tart.run/) - macOS/Linux VMs using Virtualization.framework

### Technical Resources

- [WWDC22: Create macOS or Linux VMs](https://developer.apple.com/videos/play/wwdc2022/10002/)
- [vsock(7) man page](https://man7.org/linux/man-pages/man7/vsock.7.html)
- [VirtIO specification](https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html)

---

## Appendix: File Changes Summary

### New Files

- `src/hypervisor/mod.rs` - Hypervisor trait and common types
- `src/hypervisor/virtualization.rs` - macOS implementation
- `src/platform/mod.rs` - Platform detection and utilities
- `src/platform/macos.rs` - macOS-specific utilities
- `src/platform/linux.rs` - Linux-specific utilities
- `entitlements.plist` - macOS entitlements for code signing

### Modified Files

- `src/main.rs` - Use platform abstraction
- `src/firecracker.rs` → `src/hypervisor/firecracker.rs` - Refactor to implement trait
- `src/embed.rs` - Platform-specific embedding logic
- `src/fileshare.rs` - Optional VirtioFS support
- `Cargo.toml` - New dependencies and features
- `.github/workflows/` - macOS CI jobs
- `Dockerfile` - Multi-platform build support

### Unchanged (vsock-based, portable)

- `src/socks5.rs` - Works via abstracted vsock
- `src/raw_udp.rs` - Works via abstracted vsock
- `src/vm_console.rs` - Works via abstracted vsock
- `src/console.rs` - Pure data types
- `src/ssh_launcher.rs` - Minor path adjustments only
- `src/wireguard.rs` - Config parsing only
- `src/vminit.rs` - Runs inside Linux guest, unchanged
