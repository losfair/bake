use serde::{Deserialize, Serialize};

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
