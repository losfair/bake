use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufStream},
    net::UnixStream,
};

pub fn align_up(value: usize, align: usize) -> usize {
    assert_eq!(align.count_ones(), 1);
    (value + (align - 1)) & !(align - 1)
}

pub async fn vsock_uds_connect(uds_path: &str, port: u32) -> anyhow::Result<BufStream<UnixStream>> {
    'outer: loop {
        let stream = UnixStream::connect(uds_path).await?;
        let mut stream = BufStream::new(stream);
        stream
            .write_all(format!("CONNECT {}\n", port).as_bytes())
            .await?;
        stream.flush().await?;

        let mut recv_buf = [0u8; 64];
        let mut recv_cursor = 0usize;
        loop {
            let b = match stream.read_u8().await {
                Ok(b) => b,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        continue 'outer;
                    }
                    return Err(e.into());
                }
            };
            if b == b'\n' {
                break;
            }

            if recv_cursor == recv_buf.len() {
                anyhow::bail!("buffer overflow");
            }
            recv_buf[recv_cursor] = b;
            recv_cursor += 1;
        }
        let msg = std::str::from_utf8(&recv_buf[..recv_cursor])?;
        if !msg.starts_with("OK ") {
            anyhow::bail!("unexpected response: {}", msg);
        }

        return Ok(stream);
    }
}
