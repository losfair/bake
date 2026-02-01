//! Platform-specific utilities.
//!
//! This module provides platform abstractions for:
//! - Memory-backed file creation (memfd on Linux, temp files on macOS)
//! - Process executable path detection
//! - Process lifecycle management

use std::fs::Permissions;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

/// Create a memory-backed or temporary file with the given data.
///
/// On Linux, this creates a memfd with sealing.
/// On macOS, this creates a temporary file.
///
/// Returns a path that can be used to access the file.
#[cfg(target_os = "linux")]
pub fn create_memfd(name: &str, data: &[u8], permissions: Permissions) -> anyhow::Result<String> {
    linux::create_memfd(name, data, permissions)
}

#[cfg(target_os = "macos")]
pub fn create_memfd(name: &str, data: &[u8], permissions: Permissions) -> anyhow::Result<String> {
    macos::create_temp_file(name, data, permissions)
}

/// Create a memory-backed file from an existing memory-mapped region.
///
/// On Linux, this creates a memfd and advises the kernel to drop the original pages.
/// On macOS, this creates a temporary file.
#[cfg(target_os = "linux")]
pub unsafe fn create_memfd_from_mmap(
    name: &str,
    data: &'static [u8],
    permissions: Permissions,
) -> anyhow::Result<String> {
    unsafe { linux::memfd_from_mmap(name, data, permissions) }
}

#[cfg(target_os = "macos")]
pub unsafe fn create_memfd_from_mmap(
    name: &str,
    data: &'static [u8],
    permissions: Permissions,
) -> anyhow::Result<String> {
    macos::create_temp_file(name, data, permissions)
}

/// Get the path to the current executable.
///
/// On Linux, this returns /proc/self/exe or a file descriptor path.
/// On macOS, this uses _NSGetExecutablePath.
#[allow(dead_code)]
pub fn get_executable_path() -> anyhow::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    return linux::get_executable_path();

    #[cfg(target_os = "macos")]
    return macos::get_executable_path();
}

/// Open the current executable for reading without O_CLOEXEC.
///
/// Returns the file descriptor number.
#[cfg(target_os = "linux")]
pub fn open_self_exe_fd() -> anyhow::Result<i32> {
    linux::open_self_exe_fd()
}

#[cfg(target_os = "macos")]
pub fn open_self_exe_fd() -> anyhow::Result<i32> {
    macos::open_self_exe_fd()
}

/// Create a temporary file with the given data (macOS only).
///
/// This is a direct re-export of the macOS temp file creation for use
/// in platform-specific code that explicitly needs temp files.
#[cfg(target_os = "macos")]
pub fn create_temp_file(name: &str, data: &[u8], permissions: Permissions) -> anyhow::Result<String> {
    macos::create_temp_file(name, data, permissions)
}
