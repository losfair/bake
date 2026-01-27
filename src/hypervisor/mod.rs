//! Platform-agnostic hypervisor abstraction layer.
//!
//! This module provides a unified interface for running virtual machines across
//! different platforms:
//! - Linux: Firecracker + KVM
//! - macOS: Apple Virtualization.framework

use std::os::fd::OwnedFd;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
pub mod firecracker;
#[cfg(target_os = "linux")]
pub use firecracker::FirecrackerVm as PlatformVm;

#[cfg(target_os = "macos")]
pub mod virtualization;
#[cfg(target_os = "macos")]
pub use virtualization::VirtualizationVm as PlatformVm;

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
    pub id: String,
    /// Path to the disk image on host
    pub path: PathBuf,
    /// Whether the drive is read-only
    pub read_only: bool,
}

/// Handle to a resource (kernel, initrd, rootfs).
#[derive(Debug, Clone)]
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
    /// VM is ready to start
    Ready,
    /// VM is running
    Running,
    /// VM has stopped
    Stopped,
    /// VM encountered an error
    Error,
}

/// A connected vsock stream.
///
/// This is a platform-agnostic wrapper around vsock connections.
pub struct VsockStream {
    inner: VsockStreamInner,
}

enum VsockStreamInner {
    #[cfg(target_os = "linux")]
    Unix(tokio::net::UnixStream),
    #[cfg(target_os = "macos")]
    Macos(OwnedFd),
}

impl VsockStream {
    /// Create from a Unix stream (used on Linux with Firecracker's vsock proxy).
    #[cfg(target_os = "linux")]
    pub fn from_unix(stream: tokio::net::UnixStream) -> Self {
        Self {
            inner: VsockStreamInner::Unix(stream),
        }
    }

    /// Create from a raw file descriptor (used on macOS).
    #[cfg(target_os = "macos")]
    pub fn from_fd(fd: OwnedFd) -> Self {
        Self {
            inner: VsockStreamInner::Macos(fd),
        }
    }

    /// Convert to a standard owned file descriptor.
    pub fn into_fd(self) -> std::io::Result<OwnedFd> {
        match self.inner {
            #[cfg(target_os = "linux")]
            VsockStreamInner::Unix(stream) => {
                use std::os::unix::io::IntoRawFd;
                let std_stream = stream.into_std()?;
                Ok(unsafe { OwnedFd::from_raw_fd(std_stream.into_raw_fd()) })
            }
            #[cfg(target_os = "macos")]
            VsockStreamInner::Macos(fd) => Ok(fd),
        }
    }

    /// Get a reference to the inner Unix stream (Linux only).
    #[cfg(target_os = "linux")]
    pub fn as_unix_stream(&mut self) -> Option<&mut tokio::net::UnixStream> {
        match &mut self.inner {
            VsockStreamInner::Unix(stream) => Some(stream),
        }
    }
}

#[cfg(target_os = "linux")]
use std::os::unix::io::FromRawFd;

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
    fn vsock_connect_path(&self) -> &std::path::Path;

    /// Get the path pattern for vsock listeners (e.g., "/path/fc.sock_{port}").
    fn vsock_listen_path(&self, port: u32) -> PathBuf;

    /// Get the current state of the VM.
    fn state(&self) -> VmState;
}

/// Connect to a vsock port through the platform's vsock proxy.
///
/// On Linux, this connects to Firecracker's Unix socket and sends a CONNECT command.
/// On macOS, this uses Virtualization.framework's vsock device.
pub async fn vsock_connect(
    uds_path: &std::path::Path,
    port: u32,
) -> HypervisorResult<tokio::net::UnixStream> {
    crate::util::vsock_uds_connect(uds_path, port).await
}
