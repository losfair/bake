use std::os::unix::fs::MetadataExt;

pub fn launch_ssh(sel_pid: Option<i32>, ssh_args: Vec<String>) -> anyhow::Result<()> {
    use std::fs;
    use std::os::unix::process::CommandExt as _;

    // Identify this executable by (dev,inode)
    let self_meta = std::fs::metadata("/proc/self/exe")?;
    let self_dev = self_meta.dev();
    let self_ino = self_meta.ino();

    // Collect candidate PIDs whose /proc/<pid>/exe matches our (dev,ino)
    struct Candidate {
        pid: i32,
        ssh_proxy_fd: i32,
        id_ecdsa_fd: i32,
    }

    let mut candidates: Vec<Candidate> = Vec::new();

    let mut collect_for_pid = |pid: i32| {
        let exe_meta = match fs::metadata(format!("/proc/{}/exe", pid)) {
            Ok(m) => m,
            Err(_) => return,
        };
        if exe_meta.dev() != self_dev || exe_meta.ino() != self_ino {
            return;
        }
        let mut ssh_proxy_fd: Option<i32> = None;
        let mut id_ecdsa_fd: Option<i32> = None;
        let fd_dir = format!("/proc/{}/fd", pid);
        let Ok(fd_iter) = fs::read_dir(&fd_dir) else {
            return;
        };
        for fdent in fd_iter.flatten() {
            let fd_name = fdent.file_name();
            let fd_str = match fd_name.to_str() {
                Some(s) => s,
                None => continue,
            };
            let fd_num: i32 = match fd_str.parse() {
                Ok(n) => n,
                Err(_) => continue,
            };
            let link_target = match fs::read_link(fdent.path()) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let lt = link_target.as_os_str().as_encoded_bytes();
            if lt == b"/memfd:ssh_proxy_path (deleted)" {
                ssh_proxy_fd = Some(fd_num);
            } else if lt == b"/memfd:id_ecdsa (deleted)" {
                id_ecdsa_fd = Some(fd_num);
            }
            if ssh_proxy_fd.is_some() && id_ecdsa_fd.is_some() {
                break;
            }
        }
        if let (Some(ssh_fd), Some(key_fd)) = (ssh_proxy_fd, id_ecdsa_fd) {
            candidates.push(Candidate {
                pid,
                ssh_proxy_fd: ssh_fd,
                id_ecdsa_fd: key_fd,
            });
        }
    };

    if let Some(target) = sel_pid {
        collect_for_pid(target);
    } else {
        for entry in fs::read_dir("/proc")? {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let file_name = entry.file_name();
            let name = match file_name.to_str() {
                Some(s) => s,
                None => continue,
            };
            if !name.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let pid: i32 = match name.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            collect_for_pid(pid);
        }
    }

    match candidates.len() {
        0 => {
            if let Some(p) = sel_pid {
                anyhow::bail!("specified pid {} is not a matching running instance", p);
            } else {
                eprintln!("No running instance of this binary with SSH detected.");
                eprintln!(
                    "Start it first, then run: {} ssh",
                    std::env::args().next().unwrap_or_else(|| "app.elf".into())
                );
                anyhow::bail!("no running instance found");
            }
        }
        n if n > 1 => {
            let mut pids: Vec<String> = candidates.iter().map(|c| c.pid.to_string()).collect();
            pids.sort();
            eprintln!("Multiple running instances detected: {}", pids.join(", "));
            eprintln!("Please specify which to connect to by stopping others.");
            anyhow::bail!("multiple instances");
        }
        _ => {}
    }

    let c = &candidates[0];

    // Read the proxy socket path from the other process' memfd
    let proxy_path_bytes = fs::read(format!("/proc/{}/fd/{}", c.pid, c.ssh_proxy_fd))?;
    // Trim trailing newlines/NULs, then build a UTF-8 string if possible
    let mut proxy_path = String::from_utf8_lossy(&proxy_path_bytes).to_string();
    proxy_path.truncate(proxy_path.trim_end_matches(['\n', '\0']).len());

    // Build ssh invocation
    let mut cmd = std::process::Command::new("ssh");
    cmd.arg("-o").arg(format!(
        "ProxyCommand=nc -U {}",
        shell_escape::escape(std::borrow::Cow::Borrowed(proxy_path.as_str()))
    ));
    cmd.arg("-i")
        .arg(format!("/proc/{}/fd/{}", c.pid, c.id_ecdsa_fd));
    cmd.arg("-o").arg("UserKnownHostsFile=/dev/null");
    cmd.arg("-o").arg("StrictHostKeyChecking=no");
    cmd.arg("root@localhost");
    if !ssh_args.is_empty() {
        cmd.args(ssh_args);
    }

    Err(anyhow::anyhow!("exec failed: {:?}", cmd.exec()))
}
