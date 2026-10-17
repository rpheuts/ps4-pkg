use anyhow::{bail, Context, Result};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::io::Cursor;

const PSF_MAGIC: u32 = 0x00505346; // "\0PSF" in big-endian
const PSF_VERSION_1_0: u32 = 0x00000100;
const PSF_VERSION_1_1: u32 = 0x00000101;

#[derive(Debug, Clone)]
pub enum PsfValue {
    Binary(Vec<u8>),
    Text(String),
    Integer(i32),
}

#[derive(Debug, Clone, Default)]
pub struct Psf {
    entries: HashMap<String, PsfValue>,
}

impl Psf {
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 20 {
            bail!("PSF buffer too small ({} bytes)", buf.len());
        }

        let mut cursor = Cursor::new(buf);
        let magic = cursor.read_u32::<BigEndian>()?;
        if magic != PSF_MAGIC {
            bail!("Invalid PSF magic: 0x{:08X}", magic);
        }

        let version = cursor.read_u32::<LittleEndian>()?;
        if version != PSF_VERSION_1_1 && version != PSF_VERSION_1_0 {
            bail!("Unsupported PSF version: 0x{:08X}", version);
        }

        let key_table_offset = cursor.read_u32::<LittleEndian>()? as usize;
        let data_table_offset = cursor.read_u32::<LittleEndian>()? as usize;
        let index_table_entries = cursor.read_u32::<LittleEndian>()? as usize;

        let mut entries = HashMap::with_capacity(index_table_entries);

        for i in 0..index_table_entries {
            let entry_offset = 20 + i * 16;
            if entry_offset + 16 > buf.len() {
                bail!("PSF entry {} out of bounds", i);
            }
            let mut ec = Cursor::new(&buf[entry_offset..entry_offset + 16]);
            let key_offset = ec.read_u16::<LittleEndian>()? as usize;
            let param_fmt = ec.read_u16::<LittleEndian>()?;
            let param_len = ec.read_u32::<LittleEndian>()? as usize;
            let _param_max_len = ec.read_u32::<LittleEndian>()? as usize;
            let data_offset = ec.read_u32::<LittleEndian>()? as usize;

            let abs_key_start = key_table_offset + key_offset;
            if abs_key_start >= buf.len() {
                bail!("PSF key offset out of bounds");
            }
            let key_bytes = &buf[abs_key_start..];
            let nul_pos = key_bytes
                .iter()
                .position(|&b| b == 0)
                .context("Unterminated key in PSF key table")?;
            let key = String::from_utf8_lossy(&key_bytes[..nul_pos]).into_owned();

            let abs_data_start = data_table_offset + data_offset;
            let abs_data_end = abs_data_start + param_len;
            if abs_data_end > buf.len() {
                bail!("PSF data for key '{}' out of bounds", key);
            }
            let data_slice = &buf[abs_data_start..abs_data_end];

            let val = match param_fmt {
                0x0004 => PsfValue::Binary(data_slice.to_vec()),
                0x0204 => {
                    let end = data_slice
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(data_slice.len());
                    let text = String::from_utf8_lossy(&data_slice[..end]).into_owned();
                    PsfValue::Text(text)
                }
                0x0404 => {
                    if param_len != 4 {
                        bail!("PSF integer entry '{}' has size {}", key, param_len);
                    }
                    let mut dc = Cursor::new(data_slice);
                    PsfValue::Integer(dc.read_i32::<LittleEndian>()?)
                }
                other => bail!("Unknown PSF entry format 0x{:04X} for key '{}'", other, key),
            };

            entries.insert(key, val);
        }

        Ok(Self { entries })
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        match self.entries.get(key) {
            Some(PsfValue::Text(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn get_int(&self, key: &str) -> Option<i32> {
        match self.entries.get(key) {
            Some(PsfValue::Integer(v)) => Some(*v),
            _ => None,
        }
    }

    pub fn category(&self) -> Option<&str> {
        self.get_str("CATEGORY")
    }

    pub fn content_id(&self) -> Option<&str> {
        self.get_str("CONTENT_ID")
    }

    pub fn title_id(&self) -> Option<&str> {
        self.get_str("TITLE_ID")
    }

    pub fn title(&self) -> Option<&str> {
        self.get_str("TITLE")
    }

    pub fn app_ver(&self) -> Option<&str> {
        self.get_str("APP_VER").or_else(|| self.get_str("VERSION"))
    }

    /// Extracts the 16-character entitlement label from `CONTENT_ID`
    /// (`UPXXXX-CUSAXXXXX_XX-ENTITLEMENTLABEL`).
    pub fn entitlement_label(&self) -> Option<&str> {
        let cid = self.content_id()?;
        cid.split('-').nth(2).or_else(|| {
            if cid.len() > 20 {
                Some(&cid[20..])
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entitlement_label_extraction() {
        let mut entries = HashMap::new();
        entries.insert(
            "CONTENT_ID".to_string(),
            PsfValue::Text("EP9000-CUSA00003_00-DCXVEHICLEXX0001".to_string()),
        );
        entries.insert("CATEGORY".to_string(), PsfValue::Text("ac".to_string()));
        entries.insert(
            "TITLE_ID".to_string(),
            PsfValue::Text("CUSA00003".to_string()),
        );
        let psf = Psf { entries };
        assert_eq!(psf.category(), Some("ac"));
        assert_eq!(psf.title_id(), Some("CUSA00003"));
        assert_eq!(psf.entitlement_label(), Some("DCXVEHICLEXX0001"));
    }
}

