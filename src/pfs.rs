use anyhow::{bail, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use flate2::read::ZlibDecoder;
use std::io::{Cursor, Read};

pub const PFS_FILE: u32 = 2;
pub const PFS_DIR: u32 = 3;
pub const PFS_CURRENT_DIR: u32 = 4;
pub const PFS_PARENT_DIR: u32 = 5;

pub const PFSC_MAGIC: u32 = 0x43534650; // "PFSC" in little-endian

#[derive(Debug, Clone, Copy)]
pub struct PfsChdr {
    pub magic: i32,
    pub unk4: i32,
    pub unk8: i32,
    pub block_sz: i32,
    pub block_sz2: i64,
    pub block_offsets: i64,
    pub data_start: u64,
    pub data_length: i64,
}

impl PfsChdr {
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 48 {
            bail!("PFSC header buffer too small");
        }
        let mut c = Cursor::new(buf);
        Ok(Self {
            magic: c.read_i32::<LittleEndian>()?,
            unk4: c.read_i32::<LittleEndian>()?,
            unk8: c.read_i32::<LittleEndian>()?,
            block_sz: c.read_i32::<LittleEndian>()?,
            block_sz2: c.read_i64::<LittleEndian>()?,
            block_offsets: c.read_i64::<LittleEndian>()?,
            data_start: c.read_u64::<LittleEndian>()?,
            data_length: c.read_i64::<LittleEndian>()?,
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Inode {
    pub mode: u16,
    pub nlink: u16,
    pub flags: u32,
    pub size: i64,
    pub size_compressed: i64,
    pub blocks: u32,
    pub loc: u32,
}

impl Inode {
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 0x68 {
            bail!("Inode buffer too small");
        }
        let mut c = Cursor::new(buf);
        let mode = c.read_u16::<LittleEndian>()?;
        let nlink = c.read_u16::<LittleEndian>()?;
        let flags = c.read_u32::<LittleEndian>()?;
        let size = c.read_i64::<LittleEndian>()?;
        let size_compressed = c.read_i64::<LittleEndian>()?;
        // Skip timestamps/uid/gid/unk (0x60 - 0x18 = 0x48 bytes)
        c.set_position(0x60);
        let blocks = c.read_u32::<LittleEndian>()?;
        let loc = c.read_u32::<LittleEndian>()?;
        Ok(Self {
            mode,
            nlink,
            flags,
            size,
            size_compressed,
            blocks,
            loc,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Dirent {
    pub ino: u32,
    pub dtype: u32,
    pub namelen: u32,
    pub entsize: u32,
    pub name: String,
}

impl Dirent {
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 16 {
            bail!("Dirent buffer too small");
        }
        let mut c = Cursor::new(buf);
        let ino = c.read_u32::<LittleEndian>()?;
        let dtype = c.read_u32::<LittleEndian>()?;
        let namelen = c.read_u32::<LittleEndian>()?;
        let entsize = c.read_u32::<LittleEndian>()?;
        let name_end = (16 + namelen as usize).min(buf.len());
        let name = if namelen > 0 && 16 < name_end {
            String::from_utf8_lossy(&buf[16..name_end]).into_owned()
        } else {
            String::new()
        };
        Ok(Self {
            ino,
            dtype,
            namelen,
            entsize,
            name,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PfsFsEntry {
    pub name: String,
    pub inode: usize,
    pub ftype: u32,
}

/// Scans decrypted PFS image at 64 KiB boundaries starting at `0x20000` for `PFSC` magic.
pub fn get_pfsc_offset(pfs_image: &[u8]) -> Option<usize> {
    let mut i = 0x20000usize;
    while i + 4 <= pfs_image.len() {
        let val = u32::from_le_bytes(pfs_image[i..i + 4].try_into().unwrap());
        if val == PFSC_MAGIC {
            return Some(i);
        }
        i += 0x10000;
    }
    None
}

/// Decompresses a PFSC compressed block into a 64 KiB (`0x10000`) output buffer.
pub fn decompress_pfsc(compressed_data: &[u8], decompressed_data: &mut [u8]) -> Result<()> {
    decompressed_data.fill(0);
    let mut decoder = ZlibDecoder::new(compressed_data);
    let mut total = 0;
    while total < decompressed_data.len() {
        let n = decoder.read(&mut decompressed_data[total..])?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn test_pfsc_offset_and_decompression() {
        let mut fake_pfs = vec![0u8; 0x40000];
        fake_pfs[0x30000..0x30004].copy_from_slice(&PFSC_MAGIC.to_le_bytes());
        assert_eq!(get_pfsc_offset(&fake_pfs), Some(0x30000));

        let mut raw_block = vec![0u8; 0x10000];
        raw_block[0..11].copy_from_slice(b"hello world");
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&raw_block).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut decompressed = vec![0u8; 0x10000];
        decompress_pfsc(&compressed, &mut decompressed).unwrap();
        assert_eq!(&decompressed[0..11], b"hello world");
    }
}

