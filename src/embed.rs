use std::{
    fs::File,
    io::{Read, Write},
    ptr::NonNull,
};

use memmap2::Mmap;

use crate::util::align_up;

const MAGIC: [u8; 56] = *b"fd9b84110b992e9bc0e7bf44f166abe83fad5dc2a281271c5193BAKE";

pub fn write_embedded_data(
    data: &mut [&mut dyn Read],
    w: &mut impl Write,
    current_size: usize,
) -> std::io::Result<()> {
    // align to 512 bytes
    const ALIGN: usize = 512;
    let alignment_fill_bytes = align_up(current_size, ALIGN) - current_size;
    assert!(alignment_fill_bytes < ALIGN);
    w.write_all(&vec![0u8; alignment_fill_bytes])?;
    let mut len = 0usize;
    for data in data {
        let n = std::io::copy(data, w)?;
        len += n as usize;
    }
    w.write_all(&(len as u64).to_le_bytes())?;
    w.write_all(&MAGIC)?;
    Ok(())
}

#[derive(Copy, Clone)]
pub struct EmbeddedInfo {
    pub base: NonNull<u8>,
    pub data: &'static [u8],
}

unsafe impl Send for EmbeddedInfo {}
unsafe impl Sync for EmbeddedInfo {}

/// Get the path to the current executable in a cross-platform way.
fn get_exe_path() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Some(std::path::PathBuf::from("/proc/self/exe"))
    }

    #[cfg(target_os = "macos")]
    {
        crate::platform::get_executable_path().ok()
    }
}

pub fn get_embedded_data() -> Option<EmbeddedInfo> {
    let exe_path = get_exe_path()?;
    let me_ = unsafe { Mmap::map(&File::open(&exe_path).ok()?) }.ok()?;

    // truncate to first non-zero byte
    let mut me = unsafe { std::mem::transmute::<&[u8], &[u8]>(&me_[..]) };
    std::mem::forget(me_);
    while me.len() > 0 && me[me.len() - 1] == 0 {
        me = &me[..me.len() - 1];
    }

    if me.len() < 64 {
        return None;
    };

    let (prefix, trailer) = me.split_at(me.len() - 64);
    if &trailer[8..64] != &MAGIC[..] {
        return None;
    }
    let len = u64::from_le_bytes(trailer[0..8].try_into().unwrap()) as usize;
    if prefix.len() < len {
        return None;
    };
    let data: &'static [u8] =
        unsafe { std::mem::transmute::<&[u8], &'static [u8]>(&prefix[prefix.len() - len..]) };
    let base = NonNull::from(me.as_ref()).cast::<u8>();
    return Some(EmbeddedInfo { base, data });
}
