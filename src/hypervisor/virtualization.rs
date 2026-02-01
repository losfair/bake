//! macOS Virtualization.framework hypervisor implementation.
//!
//! This module provides the macOS-specific VM implementation using Apple's
//! Virtualization.framework.

// Link against Virtualization.framework
#[link(name = "Virtualization", kind = "framework")]
unsafe extern "C" {}

use std::ffi::c_void;
use std::fs::{File, Permissions};
use std::io::Read as _;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use block2::StackBlock;
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject, Bool};
use objc2::{class, msg_send, msg_send_id};
use objc2_foundation::{NSError, NSMutableArray, NSString, NSURL};

use super::{
    create_ephemeral_disk, EmbeddedSource, Hypervisor, HypervisorResult, ResourceHandle, VmConfig,
    VmState,
};
use crate::platform;

/// Thread-safe wrapper for ObjC objects.
///
/// This is safe because we ensure the objects are only accessed from appropriate contexts
/// and the Virtualization.framework objects we use are thread-safe when accessed via
/// the dispatch queue pattern.
struct SendableObjc(*mut AnyObject);
unsafe impl Send for SendableObjc {}
unsafe impl Sync for SendableObjc {}

impl SendableObjc {
    fn new(obj: *mut AnyObject) -> Self {
        Self(obj)
    }

    fn as_ptr(&self) -> *mut AnyObject {
        self.0
    }

    fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl Clone for SendableObjc {
    fn clone(&self) -> Self {
        if !self.0.is_null() {
            unsafe {
                let _: *mut AnyObject = msg_send![self.0, retain];
            }
        }
        Self(self.0)
    }
}

impl Drop for SendableObjc {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _: () = msg_send![self.0, release];
            }
        }
    }
}

/// Virtualization.framework VM instance.
pub struct VirtualizationVm {
    config: VmConfig,
    state: VmState,
    /// Path to the vsock outbound Unix socket (simulated via vsock device)
    vsock_uds_path: PathBuf,
    /// Temp files that need to stay alive
    _temp_files: Vec<TempResource>,
    /// The actual VM instance (wrapped for Send)
    vm: Option<SendableObjc>,
    /// Vsock device for guest communication (wrapped for Send)
    vsock_device: Option<SendableObjc>,
    /// Queue for VM operations (wrapped for Send)
    queue: Option<SendableObjc>,
}

struct TempResource {
    _dir: Option<tempfile::TempDir>,
    path: PathBuf,
}

// MARK: - Virtualization.framework bindings

fn vz_virtual_machine_configuration_class() -> &'static AnyClass {
    class!(VZVirtualMachineConfiguration)
}

fn vz_linux_boot_loader_class() -> &'static AnyClass {
    class!(VZLinuxBootLoader)
}

fn vz_virtio_block_device_configuration_class() -> &'static AnyClass {
    class!(VZVirtioBlockDeviceConfiguration)
}

fn vz_disk_image_storage_device_attachment_class() -> &'static AnyClass {
    class!(VZDiskImageStorageDeviceAttachment)
}

fn vz_virtio_socket_device_configuration_class() -> &'static AnyClass {
    class!(VZVirtioSocketDeviceConfiguration)
}

fn vz_virtio_console_device_configuration_class() -> &'static AnyClass {
    class!(VZVirtioConsoleDeviceConfiguration)
}

fn vz_virtio_console_port_configuration_class() -> &'static AnyClass {
    class!(VZVirtioConsolePortConfiguration)
}

fn vz_file_handle_serial_port_attachment_class() -> &'static AnyClass {
    class!(VZFileHandleSerialPortAttachment)
}

fn vz_virtual_machine_class() -> &'static AnyClass {
    class!(VZVirtualMachine)
}

impl Hypervisor for VirtualizationVm {
    fn create(config: VmConfig) -> HypervisorResult<Self> {
        let vsock_uds_path = config.socket_dir.join("vz.sock");

        Ok(Self {
            config,
            state: VmState::Creating,
            vsock_uds_path,
            _temp_files: Vec::new(),
            vm: None,
            vsock_device: None,
            queue: None,
        })
    }

    fn run(&mut self) -> HypervisorResult<()> {
        self.state = VmState::Running;

        // Prepare resources
        let kernel_path = self.prepare_resource(&self.config.kernel.clone(), "kernel")?;
        let initrd_path = self.prepare_resource(&self.config.initrd.clone(), "initrd")?;
        let rootfs_path = self.prepare_resource(&self.config.rootfs.clone(), "rootfs")?;

        // Create ephemeral disk
        let ephemeral_path = self.config.socket_dir.join("ephemeral.img");
        create_ephemeral_disk(&ephemeral_path, self.config.ephemeral_disk_mb)?;

        unsafe {
            // Create VM configuration
            let vz_config: *mut AnyObject = msg_send![vz_virtual_machine_configuration_class(), new];

            // Set CPU count
            let _: () = msg_send![vz_config, setCPUCount: self.config.cpus as usize];

            // Set memory size (in bytes)
            let memory_bytes = self.config.memory_mb as u64 * 1024 * 1024;
            let _: () = msg_send![vz_config, setMemorySize: memory_bytes];

            // Create boot loader
            let kernel_url = create_nsurl(&kernel_path)?;
            let boot_loader: *mut AnyObject = msg_send![vz_linux_boot_loader_class(), alloc];
            let boot_loader: *mut AnyObject = msg_send![boot_loader, initWithKernelURL: &*kernel_url];

            // Set initrd
            let initrd_url = create_nsurl(&initrd_path)?;
            let _: () = msg_send![boot_loader, setInitialRamdiskURL: &*initrd_url];

            // Set boot arguments
            let boot_args_ns = NSString::from_str(&self.config.boot_args);
            let _: () = msg_send![boot_loader, setCommandLine: &*boot_args_ns];

            // Attach boot loader to config
            let _: () = msg_send![vz_config, setBootLoader: boot_loader];

            // Create storage devices array
            let storage_devices: Retained<NSMutableArray<AnyObject>> = NSMutableArray::new();

            // Add rootfs as read-only disk image
            // NOTE: On macOS, VZDiskImageStorageDeviceAttachment validates disk format,
            // so we can't use the executable directly. The rootfs must be extracted first.
            let rootfs_attachment = create_disk_image_attachment(&rootfs_path, true)?;
            let rootfs_block: *mut AnyObject = msg_send![vz_virtio_block_device_configuration_class(), alloc];
            let rootfs_block: *mut AnyObject = msg_send![rootfs_block, initWithAttachment: rootfs_attachment];
            let _: () = msg_send![&*storage_devices, addObject: rootfs_block];

            // Add ephemeral disk as read-write (use disk image attachment for proper sparse disk)
            let ephemeral_attachment =
                create_disk_image_attachment(&ephemeral_path.to_string_lossy(), false)?;
            let ephemeral_block: *mut AnyObject = msg_send![vz_virtio_block_device_configuration_class(), alloc];
            let ephemeral_block: *mut AnyObject = msg_send![ephemeral_block, initWithAttachment: ephemeral_attachment];
            let _: () = msg_send![&*storage_devices, addObject: ephemeral_block];

            // Add extra drives (volumes) using disk image attachment
            for drive in &self.config.extra_drives {
                let attachment =
                    create_disk_image_attachment(&drive.path.to_string_lossy(), drive.read_only)?;
                let block: *mut AnyObject = msg_send![vz_virtio_block_device_configuration_class(), alloc];
                let block: *mut AnyObject = msg_send![block, initWithAttachment: attachment];
                let _: () = msg_send![&*storage_devices, addObject: block];
            }

            // Set storage devices
            let _: () = msg_send![vz_config, setStorageDevices: &*storage_devices];

            // Create vsock device
            let vsock_config: *mut AnyObject = msg_send![vz_virtio_socket_device_configuration_class(), new];
            let socket_devices: Retained<NSMutableArray<AnyObject>> = NSMutableArray::new();
            let _: () = msg_send![&*socket_devices, addObject: vsock_config];
            let _: () = msg_send![vz_config, setSocketDevices: &*socket_devices];

            // Create console device for serial I/O
            let console_config = self.create_console_config()?;
            let console_devices: Retained<NSMutableArray<AnyObject>> = NSMutableArray::new();
            let _: () = msg_send![&*console_devices, addObject: console_config];
            let _: () = msg_send![vz_config, setConsoleDevices: &*console_devices];

            // Validate configuration
            let mut error: *mut NSError = std::ptr::null_mut();
            let valid: Bool = msg_send![
                vz_config,
                validateWithError: &mut error as *mut *mut NSError
            ];

            if !valid.as_bool() {
                if !error.is_null() {
                    let desc: Retained<NSString> = msg_send_id![&*error, localizedDescription];
                    anyhow::bail!(
                        "VM configuration validation failed: {}",
                        desc.to_string()
                    );
                }
                anyhow::bail!("VM configuration validation failed");
            }

            // Create dispatch queue for VM
            let queue_label = std::ffi::CString::new("com.bake.vm").unwrap();
            let queue: *mut AnyObject = dispatch_queue_create(
                queue_label.as_ptr(),
                std::ptr::null(),
            );
            if queue.is_null() {
                anyhow::bail!("failed to create dispatch queue");
            }
            self.queue = Some(SendableObjc::new(queue));

            // Create VM
            let vm: *mut AnyObject = msg_send![vz_virtual_machine_class(), alloc];
            let vm: *mut AnyObject = msg_send![vm, initWithConfiguration: vz_config queue: queue];
            self.vm = Some(SendableObjc::new(vm));

            // Get vsock device from VM for later use
            let socket_devices: *mut AnyObject = msg_send![vm, socketDevices];
            let count: usize = msg_send![socket_devices, count];
            if count > 0 {
                let vsock: *mut AnyObject = msg_send![socket_devices, objectAtIndex: 0usize];
                let vsock: *mut AnyObject = msg_send![vsock, retain];
                self.vsock_device = Some(SendableObjc::new(vsock));
            }

            // Start vsock listener service
            self.start_vsock_listener()?;

            // Create semaphores for start completion and VM stop
            let start_semaphore = dispatch_semaphore_create(0);
            let start_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

            // Context for the dispatch callback
            struct StartContext {
                vm: *mut AnyObject,
                semaphore: *mut c_void,
                error: Arc<Mutex<Option<String>>>,
            }

            unsafe extern "C" fn start_vm_on_queue(context: *mut c_void) {
                let ctx = Box::from_raw(context as *mut StartContext);
                let semaphore_ptr = ctx.semaphore as usize;
                let error_arc = ctx.error.clone();

                let completion_block = StackBlock::new(move |error: *mut NSError| {
                    if !error.is_null() {
                        let desc: Retained<NSString> = msg_send_id![&*error, localizedDescription];
                        *error_arc.lock().unwrap() = Some(desc.to_string());
                    }
                    dispatch_semaphore_signal(semaphore_ptr as *mut c_void);
                });

                let _: () = msg_send![ctx.vm, startWithCompletionHandler: &completion_block];
            }

            let ctx = Box::into_raw(Box::new(StartContext {
                vm,
                semaphore: start_semaphore,
                error: start_error.clone(),
            }));

            // Dispatch the start call to the VM's queue
            dispatch_async_f(queue, ctx as *mut c_void, start_vm_on_queue);

            // Wait for VM to start
            dispatch_semaphore_wait(start_semaphore, DISPATCH_TIME_FOREVER);
            dispatch_release(start_semaphore as *mut c_void);

            // Check for start error
            if let Some(err) = start_error.lock().unwrap().take() {
                anyhow::bail!("VM failed to start: {}", err);
            }

            // VM state constants
            const VZ_VM_STATE_STOPPED: i64 = 0;
            const VZ_VM_STATE_RUNNING: i64 = 1;
            const VZ_VM_STATE_ERROR: i64 = 3;

            // Poll VM state until it stops
            loop {
                let state: i64 = msg_send![vm, state];
                match state {
                    VZ_VM_STATE_STOPPED => break,
                    VZ_VM_STATE_ERROR => {
                        eprintln!("VM entered error state");
                        break;
                    }
                    VZ_VM_STATE_RUNNING => {
                        // Still running, sleep and check again
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    _ => {
                        // Other transitional states, keep waiting
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            }
        }

        self.state = VmState::Stopped;
        Ok(())
    }

    fn vsock_connect_path(&self) -> &Path {
        &self.vsock_uds_path
    }

    fn vsock_listen_path(&self, port: u32) -> PathBuf {
        self.config.socket_dir.join(format!("vz.sock_{}", port))
    }

    fn state(&self) -> VmState {
        self.state
    }
}

impl VirtualizationVm {
    /// Prepare a resource for use by the VM, returning its path.
    fn prepare_resource(&mut self, handle: &ResourceHandle, name: &str) -> HypervisorResult<String> {
        match handle {
            ResourceHandle::Embedded { source, .. } => match source {
                EmbeddedSource::Fd(fd) => {
                    // On macOS, we need to extract embedded data to a temp file
                    // Read from the fd and write to temp file
                    let mut file = unsafe { File::from_raw_fd(*fd) };
                    let mut data = Vec::new();
                    file.read_to_end(&mut data)?;
                    // Don't close the fd, we borrowed it
                    std::mem::forget(file);

                    let path = platform::create_temp_file(name, &data, Permissions::from_mode(0o644))?;
                    self._temp_files.push(TempResource {
                        _dir: None,
                        path: PathBuf::from(&path),
                    });
                    Ok(path)
                }
                EmbeddedSource::Path(path) => Ok(path.to_string_lossy().into_owned()),
            },
            ResourceHandle::File(path) => Ok(path.to_string_lossy().into_owned()),
            ResourceHandle::Memory(data) => {
                let path = platform::create_temp_file(name, data, Permissions::from_mode(0o644))?;
                self._temp_files.push(TempResource {
                    _dir: None,
                    path: PathBuf::from(&path),
                });
                Ok(path)
            }
        }
    }

    /// Create console device configuration for serial I/O.
    unsafe fn create_console_config(&self) -> HypervisorResult<*mut AnyObject> {
        // Duplicate file descriptors so they're owned by NSFileHandle
        let stdin_fd = libc::dup(libc::STDIN_FILENO);
        let stdout_fd = libc::dup(libc::STDOUT_FILENO);
        if stdin_fd < 0 || stdout_fd < 0 {
            anyhow::bail!("failed to dup stdin/stdout");
        }

        // Create NSFileHandle objects from file descriptors
        let stdin_handle: *mut AnyObject = msg_send![class!(NSFileHandle), alloc];
        let stdin_handle: *mut AnyObject = msg_send![stdin_handle, initWithFileDescriptor: stdin_fd closeOnDealloc: Bool::YES];

        let stdout_handle: *mut AnyObject = msg_send![class!(NSFileHandle), alloc];
        let stdout_handle: *mut AnyObject = msg_send![stdout_handle, initWithFileDescriptor: stdout_fd closeOnDealloc: Bool::YES];

        // Create serial port attachment with file handles
        let attachment: *mut AnyObject = msg_send![vz_file_handle_serial_port_attachment_class(), alloc];
        let attachment: *mut AnyObject = msg_send![
            attachment,
            initWithFileHandleForReading: stdin_handle
            fileHandleForWriting: stdout_handle
        ];

        // Create a console port configuration
        let port_config: *mut AnyObject = msg_send![vz_virtio_console_port_configuration_class(), new];
        let _: () = msg_send![port_config, setAttachment: attachment];
        // Mark as the primary console port
        let _: () = msg_send![port_config, setIsConsole: Bool::YES];

        // Create console device configuration
        let console_device: *mut AnyObject = msg_send![vz_virtio_console_device_configuration_class(), new];

        // Set port at index 0 using setObject:atIndexedSubscript:
        let ports: *mut AnyObject = msg_send![console_device, ports];
        let _: () = msg_send![ports, setObject: port_config atIndexedSubscript: 0usize];

        Ok(console_device)
    }

    /// Start the vsock listener service.
    ///
    /// This creates Unix sockets for each vsock port and handles the protocol
    /// translation between Unix sockets and Virtualization.framework's vsock.
    fn start_vsock_listener(&self) -> HypervisorResult<()> {
        let Some(vsock_device) = &self.vsock_device else {
            return Ok(());
        };

        // Create the main vsock Unix socket for outbound connections
        let vsock_path = self.vsock_uds_path.clone();
        let vsock_device = vsock_device.clone();

        std::thread::spawn(move || {
            if let Err(e) = run_vsock_proxy(vsock_path, vsock_device) {
                eprintln!("vsock proxy error: {:?}", e);
            }
        });

        Ok(())
    }
}

// MARK: - Helper functions

unsafe fn create_nsurl(path: &str) -> HypervisorResult<Retained<NSURL>> {
    let path_str = NSString::from_str(path);
    let url: Option<Retained<NSURL>> = msg_send_id![class!(NSURL), fileURLWithPath: &*path_str];
    url.ok_or_else(|| anyhow::anyhow!("failed to create NSURL for path: {}", path))
}

// VZDiskImageCachingMode values
const VZ_DISK_IMAGE_CACHING_MODE_AUTOMATIC: i64 = 0;
#[allow(dead_code)]
const VZ_DISK_IMAGE_CACHING_MODE_UNCACHED: i64 = 1;
#[allow(dead_code)]
const VZ_DISK_IMAGE_CACHING_MODE_CACHED: i64 = 2;

// VZDiskImageSynchronizationMode values
#[allow(dead_code)]
const VZ_DISK_IMAGE_SYNCHRONIZATION_MODE_AUTOMATIC: i64 = 0;
const VZ_DISK_IMAGE_SYNCHRONIZATION_MODE_FSYNC: i64 = 1;
#[allow(dead_code)]
const VZ_DISK_IMAGE_SYNCHRONIZATION_MODE_NONE: i64 = 2;

/// Create a disk attachment using VZDiskImageStorageDeviceAttachment.
/// Uses explicit caching/sync modes to avoid "user data not supported" errors with raw images.
unsafe fn create_disk_image_attachment(
    path: &str,
    read_only: bool,
) -> HypervisorResult<*mut AnyObject> {
    unsafe {
        let url = create_nsurl(path)?;
        let mut error: *mut NSError = std::ptr::null_mut();

        let attachment: *mut AnyObject = msg_send![
            vz_disk_image_storage_device_attachment_class(),
            alloc
        ];
        // Use explicit caching and synchronization modes to avoid automatic detection
        // which can fail on raw disk images with "user data not supported" error
        let attachment: *mut AnyObject = msg_send![
            attachment,
            initWithURL: &*url
            readOnly: Bool::from(read_only)
            cachingMode: VZ_DISK_IMAGE_CACHING_MODE_AUTOMATIC
            synchronizationMode: VZ_DISK_IMAGE_SYNCHRONIZATION_MODE_FSYNC
            error: &mut error as *mut *mut NSError
        ];

        if attachment.is_null() {
            if !error.is_null() {
                let desc: Retained<NSString> = msg_send_id![&*error, localizedDescription];
                anyhow::bail!("failed to create disk image attachment: {}", desc.to_string());
            }
            anyhow::bail!("failed to create disk image attachment for: {}", path);
        }

        Ok(attachment)
    }
}

/// Run the vsock proxy that translates between Unix sockets and VZ vsock.
fn run_vsock_proxy(socket_path: PathBuf, vsock_device: SendableObjc) -> HypervisorResult<()> {
    use std::os::unix::net::UnixListener;

    // Remove existing socket
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path).context("failed to bind vsock proxy socket")?;

    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            continue;
        };

        let vsock_device = vsock_device.clone();

        std::thread::spawn(move || {
            // Read the CONNECT command
            let mut buf = [0u8; 128];
            let mut cursor = 0;

            loop {
                let n = match std::io::Read::read(&mut stream, &mut buf[cursor..]) {
                    Ok(0) => return,
                    Ok(n) => n,
                    Err(_) => return,
                };
                cursor += n;

                if let Some(pos) = buf[..cursor].iter().position(|&b| b == b'\n') {
                    let line = std::str::from_utf8(&buf[..pos]).unwrap_or("");
                    if let Some(port_str) = line.strip_prefix("CONNECT ") {
                        if let Ok(port) = port_str.trim().parse::<u32>() {
                            // Connect to the guest via vsock
                            if let Err(e) = handle_vsock_connect(&mut stream, &vsock_device, port) {
                                eprintln!("vsock connect error: {:?}", e);
                            }
                        }
                    }
                    return;
                }

                if cursor >= buf.len() {
                    return;
                }
            }
        });
    }

    Ok(())
}

fn handle_vsock_connect(
    stream: &mut std::os::unix::net::UnixStream,
    vsock_device: &SendableObjc,
    port: u32,
) -> HypervisorResult<()> {
    use std::io::Write as _;

    // Use VZVirtioSocketDevice.connectToPort:completionHandler:
    // This is async, so we need to use a semaphore to wait

    let semaphore = unsafe { dispatch_semaphore_create(0) };
    let result: Arc<Mutex<Option<HypervisorResult<OwnedFd>>>> = Arc::new(Mutex::new(None));
    let result_clone = result.clone();

    let semaphore_ptr = semaphore as usize;
    let result_ptr = Arc::into_raw(result_clone) as usize;

    let completion = StackBlock::new(
        move |connection: *mut AnyObject, error: *mut NSError| {
            let result = unsafe { Arc::from_raw(result_ptr as *const Mutex<Option<HypervisorResult<OwnedFd>>>) };

            if !error.is_null() {
                let desc: Retained<NSString> =
                    unsafe { msg_send_id![&*error, localizedDescription] };
                *result.lock().unwrap() = Some(Err(anyhow::anyhow!(
                    "vsock connect failed: {}",
                    desc.to_string()
                )));
            } else if connection.is_null() {
                *result.lock().unwrap() = Some(Err(anyhow::anyhow!("vsock connect returned null")));
            } else {
                // Get file descriptor from connection
                unsafe {
                    let fd: RawFd = msg_send![connection, fileDescriptor];
                    if fd >= 0 {
                        // Dup the fd so we own it
                        let new_fd = libc::dup(fd);
                        if new_fd >= 0 {
                            *result.lock().unwrap() = Some(Ok(OwnedFd::from_raw_fd(new_fd)));
                        } else {
                            *result.lock().unwrap() =
                                Some(Err(anyhow::anyhow!("failed to dup vsock fd")));
                        }
                    } else {
                        *result.lock().unwrap() =
                            Some(Err(anyhow::anyhow!("invalid file descriptor from vsock")));
                    }
                }
            }

            unsafe {
                dispatch_semaphore_signal(semaphore_ptr as *mut c_void);
            }

            std::mem::forget(result);
        },
    );

    unsafe {
        let _: () = msg_send![
            vsock_device.as_ptr(),
            connectToPort: port
            completionHandler: &completion
        ];
    }

    // Wait for completion
    unsafe {
        dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
        dispatch_release(semaphore as *mut c_void);
    }

    // Get the result
    let fd = result
        .lock()
        .unwrap()
        .take()
        .ok_or_else(|| anyhow::anyhow!("no result from vsock connect"))??;

    // Send OK response
    stream.write_all(b"OK 0\n")?;

    // Now proxy data between the Unix stream and the vsock fd
    let unix_fd = stream.as_raw_fd();
    // Take ownership of the raw fd - we're responsible for closing it
    let vsock_fd = std::os::fd::IntoRawFd::into_raw_fd(fd);

    // Spawn thread for unix->vsock direction
    let handle = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            let n = unsafe { libc::read(unix_fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
            if n <= 0 {
                break;
            }
            let mut written = 0;
            while written < n as usize {
                let w = unsafe {
                    libc::write(
                        vsock_fd,
                        buf[written..].as_ptr() as *const c_void,
                        (n as usize) - written,
                    )
                };
                if w <= 0 {
                    return;
                }
                written += w as usize;
            }
        }
    });

    // Handle vsock->unix direction in main thread
    let mut buf = [0u8; 8192];
    loop {
        let n = unsafe { libc::read(vsock_fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        let mut written = 0;
        while written < n as usize {
            let w = unsafe {
                libc::write(
                    unix_fd,
                    buf[written..].as_ptr() as *const c_void,
                    (n as usize) - written,
                )
            };
            if w <= 0 {
                break;
            }
            written += w as usize;
        }
    }

    // Shutdown the vsock fd to unblock the reader thread, then close it
    unsafe {
        libc::shutdown(vsock_fd, libc::SHUT_RDWR);
        libc::close(vsock_fd);
    }

    // Wait for the reader thread to finish
    let _ = handle.join();

    Ok(())
}

// MARK: - libdispatch FFI

#[link(name = "System", kind = "dylib")]
unsafe extern "C" {
    fn dispatch_queue_create(label: *const i8, attr: *const c_void) -> *mut AnyObject;
    fn dispatch_async_f(
        queue: *mut AnyObject,
        context: *mut c_void,
        work: unsafe extern "C" fn(*mut c_void),
    );
    fn dispatch_semaphore_create(value: isize) -> *mut c_void;
    fn dispatch_semaphore_signal(dsema: *mut c_void) -> isize;
    fn dispatch_semaphore_wait(dsema: *mut c_void, timeout: u64) -> isize;
    fn dispatch_release(object: *mut c_void);
}

const DISPATCH_TIME_FOREVER: u64 = !0;
