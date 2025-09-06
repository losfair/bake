use std::{
    collections::BTreeMap,
    io::{BufReader, ErrorKind, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
    sync::Arc,
};

use anyhow::Context;

#[derive(Clone)]
pub struct VolumeSpec {
    pub host: String,
    pub guest: String,
    pub ro: bool,
}

pub fn spawn_file_server(specs: Vec<String>, uds_path: &Path) -> Vec<VolumeSpec> {
    let listener = UnixListener::bind(&uds_path).expect("spawn_file_server: bind failed");
    let mut volumes: Vec<VolumeSpec> = vec![];

    for spec_text in specs {
        if let Some(spec) = parse_volume(&spec_text) {
            // TODO: support read-only volumes
            if spec.ro {
                panic!(
                    "read-only volume mappings are not yet supported: {}",
                    spec_text
                );
            }
            volumes.push(spec);
        } else {
            eprintln!("invalid -v/--volume spec: {}", spec_text);
        }
    }
    let volumes_clone = volumes.clone();
    std::thread::spawn(move || serve(listener, volumes_clone));
    volumes
}

fn parse_volume(spec: &str) -> Option<VolumeSpec> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.len() {
        2 => Some(VolumeSpec {
            host: parts[0].to_string(),
            guest: parts[1].to_string(),
            ro: false,
        }),
        3 => {
            let ro = match parts[2] {
                "ro" => true,
                "rw" => false,
                _ => return None,
            };
            Some(VolumeSpec {
                host: parts[0].to_string(),
                guest: parts[1].to_string(),
                ro,
            })
        }
        _ => None,
    }
}

fn serve(listener: UnixListener, volumes: Vec<VolumeSpec>) {
    let volumes = Arc::new(volumes);
    loop {
        let (conn, _) = listener.accept().expect("failed to accept fileshare conn");
        let volumes = volumes.clone();
        std::thread::spawn(move || {
            if let Err(e) = serve_conn(conn, volumes) {
                let is_eof = e
                    .downcast_ref::<std::io::Error>()
                    .map(|x| x.kind() == ErrorKind::UnexpectedEof)
                    .unwrap_or_default();
                if !is_eof {
                    eprintln!("failed serving fileshare conn: {:?}", e);
                }
            }
        });
    }
}

fn serve_conn(conn: UnixStream, volumes: Arc<Vec<VolumeSpec>>) -> anyhow::Result<()> {
    let mut conn = BufReader::new(conn);
    let mut name_len: [u8; 4] = [0u8; 4];
    conn.read_exact(&mut name_len)?;
    let name_len = u32::from_le_bytes(name_len) as usize;
    if name_len > 256 {
        anyhow::bail!("invalid name len");
    }
    let mut name = vec![0u8; name_len];
    conn.read_exact(&mut name)?;
    let volume = volumes
        .iter()
        .find(|x| x.guest.as_bytes() == name)
        .ok_or_else(|| anyhow::anyhow!("requested volume not found"))?;
    let mut server = p9::Server::new(Path::new(&volume.host), BTreeMap::new(), BTreeMap::new())
        .with_context(|| "failed to start p9 server")?;
    let mut writebuf: Vec<u8> = vec![];
    loop {
        writebuf.clear();
        server
            .handle_message(&mut conn, &mut writebuf)
            .with_context(|| "p9 server failed")?;
        if !writebuf.is_empty() {
            conn.get_mut().write_all(&writebuf)?;
        }
    }
}
