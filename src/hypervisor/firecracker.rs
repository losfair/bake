//! Firecracker hypervisor implementation for Linux.
//!
//! This module provides the Linux-specific VM implementation using Firecracker
//! with KVM as the hypervisor backend.

use std::fs::{OpenOptions, Permissions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use super::{EmbeddedSource, Hypervisor, HypervisorResult, ResourceHandle, VmConfig, VmState};
use crate::platform;

/// Firecracker VM instance.
pub struct FirecrackerVm {
    config: VmConfig,
    state: VmState,
    /// Path to the firecracker binary (memfd path)
    firecracker_path: String,
    /// Path to the vsock outbound Unix socket
    vsock_uds_path: PathBuf,
    /// Child process handle
    child: Option<Child>,
}

impl Hypervisor for FirecrackerVm {
    fn create(config: VmConfig) -> HypervisorResult<Self> {
        let vsock_uds_path = config.socket_dir.join("fc.sock");

        Ok(Self {
            config,
            state: VmState::Creating,
            firecracker_path: String::new(),
            vsock_uds_path,
            child: None,
        })
    }

    fn run(&mut self) -> HypervisorResult<()> {
        self.state = VmState::Running;

        // Build Firecracker configuration
        let fc_config = self.build_firecracker_config()?;

        // Serialize config to memfd
        let config_json = serde_json::to_vec(&fc_config)?;
        let config_path = platform::create_memfd("config", &config_json, Permissions::from_mode(0o444))?;

        // Start firecracker process
        let mut cmd = Command::new(&self.firecracker_path);
        cmd.arg("--config-file")
            .arg(&config_path)
            .arg("--no-api")
            .arg("--enable-pci")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if !self.config.verbose {
            cmd.arg("--level").arg("error");
        }

        // Setup process death signal
        unsafe {
            let ppid = libc::getpid();
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != ppid {
                    libc::abort();
                }
                Ok(())
            });
        }

        let mut child = cmd.spawn().context("failed to spawn firecracker")?;

        // Forward stdout/stderr
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        for mut pipe in [
            Box::new(stdout) as Box<dyn Read + Send + Sync>,
            Box::new(stderr) as Box<dyn Read + Send + Sync>,
        ] {
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 4096];
                loop {
                    let Ok(n) = pipe.read(&mut buf) else {
                        break;
                    };
                    if n == 0 {
                        break;
                    }
                    let mut stdout = std::io::stdout().lock();
                    let _ = stdout.write_all(&buf[..n]);
                    let _ = stdout.flush();
                }
            });
        }

        // Wait for firecracker to exit
        let status = child.wait()?;
        self.state = VmState::Stopped;

        if status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "firecracker exited with status {}",
                status
                    .code()
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "unknown".into())
            ))
        }
    }

    fn vsock_connect_path(&self) -> &Path {
        &self.vsock_uds_path
    }

    fn vsock_listen_path(&self, port: u32) -> PathBuf {
        self.config.socket_dir.join(format!("fc.sock_{}", port))
    }

    fn state(&self) -> VmState {
        self.state
    }
}

impl FirecrackerVm {
    /// Set the firecracker binary path (from embedded resource).
    pub fn set_firecracker_path(&mut self, path: String) {
        self.firecracker_path = path;
    }

    /// Build Firecracker JSON configuration.
    fn build_firecracker_config(&self) -> HypervisorResult<FirecrackerConfig> {
        // Get kernel and initrd paths
        let kernel_path = self.resource_to_path(&self.config.kernel, "kernel")?;
        let initrd_path = self.resource_to_path(&self.config.initrd, "initrd")?;
        let rootfs_path = self.resource_to_path(&self.config.rootfs, "rootfs")?;

        // Create ephemeral disk
        let ephemeral_disk_path = self.config.socket_dir.join("ephemeral.img");
        self.create_ephemeral_disk(&ephemeral_disk_path)?;

        // Build drives list
        let mut drives = vec![
            Drive {
                drive_id: "rootfs".into(),
                is_root_device: true,
                is_read_only: true,
                io_engine: "Async".into(),
                path_on_host: rootfs_path,
            },
            Drive {
                drive_id: "ephemeral".into(),
                is_root_device: false,
                is_read_only: false,
                io_engine: "Async".into(),
                path_on_host: ephemeral_disk_path.to_string_lossy().into_owned(),
            },
        ];

        // Add extra drives (volumes)
        for (i, drive) in self.config.extra_drives.iter().enumerate() {
            drives.push(Drive {
                drive_id: format!("vol-{}", i),
                is_root_device: false,
                is_read_only: drive.read_only,
                io_engine: "Async".into(),
                path_on_host: drive.path.to_string_lossy().into_owned(),
            });
        }

        Ok(FirecrackerConfig {
            boot_source: BootSource {
                kernel_image_path: kernel_path,
                initrd_path,
                boot_args: self.config.boot_args.clone(),
            },
            drives,
            machine_config: MachineConfig {
                vcpu_count: self.config.cpus,
                mem_size_mib: self.config.memory_mb,
            },
            network_interfaces: vec![],
            vsock: VsockConfig {
                guest_cid: 3,
                uds_path: self.vsock_uds_path.to_string_lossy().into_owned(),
            },
        })
    }

    /// Convert a ResourceHandle to a file path string.
    fn resource_to_path(&self, handle: &ResourceHandle, _name: &str) -> HypervisorResult<String> {
        match handle {
            ResourceHandle::Embedded { source, .. } => {
                match source {
                    EmbeddedSource::Fd(fd) => Ok(format!("/proc/self/fd/{}", fd)),
                    EmbeddedSource::Path(path) => Ok(path.to_string_lossy().into_owned()),
                }
            }
            ResourceHandle::File(path) => Ok(path.to_string_lossy().into_owned()),
            ResourceHandle::Memory(data) => {
                let path = platform::create_memfd(_name, data, Permissions::from_mode(0o444))?;
                Ok(path)
            }
        }
    }

    /// Create the ephemeral disk as a sparse file.
    fn create_ephemeral_disk(&self, path: &Path) -> HypervisorResult<()> {
        let disk_size: u64 = self.config.ephemeral_disk_mb as u64 * 1024 * 1024;
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
}

// Firecracker configuration structures (JSON serialization)

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct FirecrackerConfig {
    pub boot_source: BootSource,
    pub drives: Vec<Drive>,
    pub machine_config: MachineConfig,
    pub network_interfaces: Vec<NetworkInterface>,
    pub vsock: VsockConfig,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct BootSource {
    pub kernel_image_path: String,
    pub initrd_path: String,
    pub boot_args: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct Drive {
    pub drive_id: String,
    pub is_root_device: bool,
    pub is_read_only: bool,
    pub io_engine: String,
    pub path_on_host: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct MachineConfig {
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct NetworkInterface {
    pub iface_id: String,
    pub guest_mac: String,
    pub host_dev_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct VsockConfig {
    pub guest_cid: u32,
    pub uds_path: String,
}
