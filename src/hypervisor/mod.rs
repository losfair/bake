//! Platform-agnostic hypervisor abstraction layer.
//!
//! This module provides a unified interface for running virtual machines across
//! different platforms:
//! - Linux: Firecracker + KVM
//! - macOS: Apple Virtualization.framework

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;

#[cfg(target_os = "linux")]
pub mod firecracker;

#[cfg(target_os = "macos")]
pub mod virtualization;

/// Platform-agnostic VM configuration.
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Path or handle to the kernel image
    pub kernel: ResourceHandle,
    /// Path or handle to the initial ramdisk
    pub initrd: ResourceHandle,
    /// Path or handle to the root filesystem
    pub rootfs: ResourceHandle,
    /// Kernel command line arguments
    pub boot_args: String,
    /// Number of vCPUs
    pub cpus: u32,
    /// Memory in MiB
    pub memory_mb: u32,
    /// Size of ephemeral disk in MiB
    pub ephemeral_disk_mb: u32,
    /// Directory for Unix sockets and temp files
    pub socket_dir: PathBuf,
    /// Additional block devices (volumes)
    pub extra_drives: Vec<DriveConfig>,
    /// Whether to enable verbose output
    pub verbose: bool,
}

/// Configuration for an additional block device.
#[derive(Debug, Clone)]
pub struct DriveConfig {
    /// Unique identifier for the drive
    #[allow(dead_code)]
    pub id: String,
    /// Path to the disk image on host
    pub path: PathBuf,
    /// Whether the drive is read-only
    pub read_only: bool,
}

/// Handle to a resource (kernel, initrd, rootfs).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ResourceHandle {
    /// Resource embedded in the binary at a specific offset
    Embedded {
        /// File descriptor or path to the binary containing embedded data
        source: EmbeddedSource,
        /// Offset in 512-byte sectors from the start of the embedded region
        offset_sectors: u64,
        /// Size in 512-byte sectors
        size_sectors: u64,
    },
    /// Resource at a file path
    File(PathBuf),
    /// Resource in memory
    Memory(Vec<u8>),
}

/// Source of embedded data.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum EmbeddedSource {
    /// File descriptor number (for /proc/self/fd/N)
    Fd(i32),
    /// Path to file
    Path(PathBuf),
}

/// State of the virtual machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    /// VM is being created
    Creating,
    /// VM is running
    Running,
    /// VM has stopped
    Stopped,
}

/// Result type for hypervisor operations.
pub type HypervisorResult<T> = anyhow::Result<T>;

/// Trait for platform-specific VM implementations.
///
/// Note: This trait is not object-safe due to the `create` method returning `Self`.
/// Use `PlatformVm` type alias for compile-time platform selection.
pub trait Hypervisor: Sized + Send {
    /// Create a new VM with the given configuration.
    fn create(config: VmConfig) -> HypervisorResult<Self>;

    /// Start the virtual machine.
    ///
    /// This method blocks until the VM exits.
    fn run(&mut self) -> HypervisorResult<()>;

    /// Get the path to connect to vsock via the outbound Unix socket.
    #[allow(dead_code)]
    fn vsock_connect_path(&self) -> &std::path::Path;

    /// Get the path pattern for vsock listeners (e.g., "/path/fc.sock_{port}").
    #[allow(dead_code)]
    fn vsock_listen_path(&self, port: u32) -> PathBuf;

    /// Get the current state of the VM.
    #[allow(dead_code)]
    fn state(&self) -> VmState;
}

/// Create a sparse ephemeral disk file.
///
/// This is shared between Firecracker and Virtualization.framework implementations.
pub fn create_ephemeral_disk(path: &Path, size_mb: u32) -> HypervisorResult<()> {
    let disk_size: u64 = size_mb as u64 * 1024 * 1024;
    let mut disk = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("failed to create ephemeral disk")?;
    disk.seek(SeekFrom::Start(disk_size - 1))
        .and_then(|_| disk.write(&[0u8]))
        .context("failed to initialize ephemeral disk")?;
    Ok(())
}
