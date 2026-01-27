//! macOS-specific platform utilities.

use std::ffi::CStr;
use std::fs::{File, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::Context;

/// Storage for temp files that need to stay alive for the VM lifetime.
static TEMP_FILES: Mutex<Vec<TempFileHandle>> = Mutex::new(Vec::new());

struct TempFileHandle {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

/// Create a temporary file with the given data.
///
/// The file is stored in a temporary directory that stays alive for the
/// lifetime of the process.
///
/// Returns the path to the temporary file.
pub fn create_temp_file(name: &str, data: &[u8], permissions: Permissions) -> anyhow::Result<String> {
    let dir = tempfile::tempdir().context("failed to create temp directory")?;
    let path = dir.path().join(name);

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(permissions.mode())
        .open(&path)
        .context("failed to create temp file")?;

    file.write_all(data)?;
    file.flush()?;
    drop(file);

    let path_str = path.to_string_lossy().into_owned();

    // Keep the temp directory alive
    TEMP_FILES.lock().unwrap().push(TempFileHandle {
        _dir: dir,
        path: path.clone(),
    });

    Ok(path_str)
}

/// Get the path to the current executable.
pub fn get_executable_path() -> anyhow::Result<PathBuf> {
    // Use _NSGetExecutablePath on macOS
    let mut buf = vec![0u8; 1024];
    let mut size: u32 = buf.len() as u32;

    unsafe extern "C" {
        fn _NSGetExecutablePath(buf: *mut i8, bufsize: *mut u32) -> i32;
    }

    let result = unsafe { _NSGetExecutablePath(buf.as_mut_ptr() as *mut i8, &mut size) };

    if result == -1 {
        // Buffer too small, resize and try again
        buf.resize(size as usize, 0);
        let result = unsafe { _NSGetExecutablePath(buf.as_mut_ptr() as *mut i8, &mut size) };
        if result != 0 {
            anyhow::bail!("_NSGetExecutablePath failed");
        }
    }

    // Find null terminator and convert to path
    let c_str = unsafe { CStr::from_ptr(buf.as_ptr() as *const i8) };
    let path = PathBuf::from(c_str.to_string_lossy().into_owned());

    // Resolve symlinks to get the real path
    std::fs::canonicalize(&path).context("failed to canonicalize executable path")
}

/// Open the current executable without O_CLOEXEC.
///
/// Returns the raw file descriptor number.
pub fn open_self_exe_fd() -> anyhow::Result<i32> {
    let path = get_executable_path()?;

    let fd = unsafe {
        libc::open(
            path.as_os_str().as_encoded_bytes().as_ptr() as *const i8,
            libc::O_RDONLY,
        )
    };

    if fd == -1 {
        return Err(io::Error::last_os_error().into());
    }

    Ok(fd)
}

/// Cleanup all temporary files.
///
/// This should be called when the process exits.
pub fn cleanup_temp_files() {
    TEMP_FILES.lock().unwrap().clear();
}
