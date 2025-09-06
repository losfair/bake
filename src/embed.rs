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

pub fn get_embedded_data() -> Option<EmbeddedInfo> {
    let me = unsafe { Mmap::map(&File::open("/proc/self/exe").ok()?) }.ok()?;
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
    std::mem::forget(me);
    return Some(EmbeddedInfo { base, data });
}
