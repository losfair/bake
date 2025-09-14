use std::{
    collections::{BTreeMap, HashSet},
    io::{BufReader, ErrorKind, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
    sync::Arc,
};

use anyhow::Context;
use landlock::{
    Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, path_beneath_rules,
};

#[derive(Clone, Debug)]
pub struct VolumeSpec {
    pub host: String,
    pub guest: String,
    pub ro: bool,
    pub ext4: bool,
    pub is_file: bool,
}

pub fn spawn_file_server(specs: Vec<String>, uds_path: &Path) -> Vec<VolumeSpec> {
    let listener = UnixListener::bind(&uds_path).expect("spawn_file_server: bind failed");
    let mut volumes: Vec<VolumeSpec> = vec![];

    for spec_text in specs {
        if let Some(spec) = parse_volume(&spec_text) {
            volumes.push(spec);
        } else {
            panic!("invalid -v/--volume spec: {}", spec_text);
        }
    }
    let volumes_clone = volumes.clone();
    std::thread::spawn(move || serve(listener, volumes_clone));
    volumes
}

fn parse_volume(spec_str: &str) -> Option<VolumeSpec> {
    let parts: Vec<&str> = spec_str.split(':').collect();
    let spec = match parts.len() {
        2 => Some(VolumeSpec {
            host: parts[0].to_string(),
            guest: parts[1].to_string(),
            ro: false,
            ext4: false,
            is_file: false,
        }),
        3 => {
            let flags = parts[2]
                .split(',')
                .map(|x| x.trim())
                .filter(|x| !x.is_empty())
                .collect::<HashSet<_>>();
            Some(VolumeSpec {
                host: parts[0].to_string(),
                guest: parts[1].to_string(),
                ro: flags.contains("ro"),
                ext4: flags.contains("ext4"),
                is_file: false,
            })
        }
        _ => None,
    };
    let mut spec = spec?;
    if !spec.guest.starts_with('/') {
        eprintln!("volume: {}: guest path must start with '/'", spec_str);
        return None;
    }
    spec.is_file = match std::fs::metadata(&spec.host) {
        Ok(x) => x.is_file(),
        Err(e) => {
            eprintln!("volume: {}: host path is inaccessible: {:?}", spec_str, e);
            return None;
        }
    };
    if spec.ext4 && !spec.is_file {
        eprintln!(
            "volume: {}: ext4 mount requested but host path is not a file",
            spec_str
        );
        return None;
    }
    Some(spec)
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
    let abi = landlock::ABI::V2;
    let ruleset = Ruleset::default().handle_access(AccessFs::from_all(abi))?;
    let status = ruleset
        .create()?
        .add_rules(path_beneath_rules(
            [volume.host.as_str()],
            if volume.ro {
                AccessFs::from_read(abi)
            } else {
                AccessFs::from_all(abi)
            },
        ))?
        .restrict_self()
        .expect("Failed to enforce ruleset");

    if status.ruleset != RulesetStatus::FullyEnforced {
        anyhow::bail!("Landlock V2 is not supported by the running kernel.");
    }

    let host_path = Path::new(&volume.host);
    let serve_dir = if volume.is_file {
        host_path.parent().unwrap_or(host_path)
    } else {
        host_path
    };
    let mut server = p9::Server::new(serve_dir, BTreeMap::new(), BTreeMap::new())
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
