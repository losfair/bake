#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum ConsoleRequest {
    // Bytes flowing from VM (pty) to host
    Data(Vec<u8>),
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum ConsoleResponse {
    // Bytes flowing from host stdin to VM (pty)
    Data(Vec<u8>),
    // TTY control: update pty window size
    SetWindowSize { rows: u16, cols: u16 },
}
