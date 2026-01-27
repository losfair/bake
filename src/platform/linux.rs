//! Linux-specific platform utilities.

use std::ffi::CString;
use std::fs::{File, Permissions};
use std::io::{self, Write};
use std::os::raw::c_char;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

use crate::util::align_up;
use crate::DEBUG;

/// Create a sealed memfd with the given data.
///
/// The memfd is not close-on-exec, allowing it to be inherited by child processes.
/// Returns a path like "/proc/self/fd/N".
pub fn create_memfd(name: &str, data: &[u8], permissions: Permissions) -> anyhow::Result<String> {
    let name_cstring = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid name for memfd"))?;

    // Create memfd without O_CLOEXEC so it can be inherited
    let fd = unsafe { libc::memfd_create(name_cstring.as_ptr(), libc::MFD_ALLOW_SEALING) };

    if fd == -1 {
        return Err(io::Error::last_os_error().into());
    }

    // Write data to memfd
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(data)?;
    file.flush()?;

    // Seal the memfd to prevent modifications
    if unsafe {
        libc::fcntl(
            fd,
            libc::F_ADD_SEALS,
            libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
        )
    } != 0
    {
        anyhow::bail!("file sealing failed: {:?}", std::io::Error::last_os_error());
    }

    // Set permissions
    if unsafe { libc::fchmod(fd, permissions.mode()) } < 0 {
        anyhow::bail!("fchmod failed: {:?}", std::io::Error::last_os_error());
    }

    // Don't close the file descriptor
    std::mem::forget(file);
    Ok(format!("/proc/self/fd/{}", fd))
}

/// Create a memfd from an existing memory-mapped region.
///
/// This function creates a memfd, writes the data, and then advises the kernel
/// to drop the original mmap pages to save memory.
///
/// # Safety
///
/// The caller must ensure that `data` points to a valid memory-mapped region
/// that remains valid for the lifetime of the VM.
pub unsafe fn memfd_from_mmap(
    name: &str,
    data: &'static [u8],
    permissions: Permissions,
) -> anyhow::Result<String> {
    unsafe {
        let pgsize = libc::sysconf(libc::_SC_PAGESIZE);
        assert!(pgsize >= 4096);
        let pgsize = pgsize as usize;

        let path = create_memfd(name, data, permissions)?;
        let ptr = data.as_ptr();
        let end = ptr.add(data.len());
        let ptr = align_up(ptr as usize, pgsize);
        let end = end as usize & !(pgsize - 1);

        if end > ptr {
            if DEBUG.load(Ordering::Relaxed) {
                eprintln!(
                    "madvise({:p}, {:#x}, MADV_DONTNEED)",
                    ptr as *mut libc::c_void,
                    end - ptr
                );
            }
            assert_eq!(
                libc::madvise(ptr as *mut libc::c_void, end - ptr, libc::MADV_DONTNEED),
                0
            );
        }
        Ok(path)
    }
}

/// Get the path to the current executable.
pub fn get_executable_path() -> anyhow::Result<PathBuf> {
    Ok(PathBuf::from("/proc/self/exe"))
}

/// Open the current executable without O_CLOEXEC.
///
/// Returns the raw file descriptor number.
pub fn open_self_exe_fd() -> anyhow::Result<i32> {
    let fd = unsafe {
        libc::open(
            b"/proc/self/exe\0".as_ptr() as *const c_char,
            libc::O_RDONLY,
        )
    };

    if fd == -1 {
        return Err(io::Error::last_os_error().into());
    }

    Ok(fd)
}

/// Setup process death signal so child dies when parent exits.
///
/// This should be called in the child process via pre_exec.
///
/// # Safety
///
/// This function must be called from a context where it is safe to call
/// libc::prctl and libc::getppid.
pub unsafe fn setup_parent_death_signal(parent_pid: i32) -> io::Result<()> {
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent_pid {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to set parent death signal",
            ));
        }
    }
    Ok(())
}
