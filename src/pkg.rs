use crate::crypto::{
    aes_cbc_decrypt, decrypt_pfs, iv_key_hash256, pfs_gen_crypto_key, rsa2048_decrypt,
};
use crate::pfs::{
    decompress_pfsc, get_pfsc_offset, Dirent, Inode, PfsChdr, PfsFsEntry, PFS_CURRENT_DIR, PFS_DIR,
    PFS_FILE,
};
use crate::pkg_type::get_entry_name_by_type;
use crate::psf::Psf;
use anyhow::{bail, Context, Result};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const PKG_MAGIC: u32 = 0x7F434E54; // "\x7FCNT"

const FLAG_FIRST_PATCH: u32 = 0x0010_0000;
const FLAG_PATCHGO: u32 = 0x0020_0000;
const FLAG_REMASTER: u32 = 0x0040_0000;
const FLAG_PS_CLOUD: u32 = 0x0080_0000;
const FLAG_GD_AC: u32 = 0x0200_0000;
const FLAG_NON_GAME: u32 = 0x0400_0000;
const FLAG_UNKNOWN_0X8000000: u32 = 0x0800_0000;
const FLAG_SUBSEQUENT_PATCH: u32 = 0x4000_0000;
const FLAG_DELTA_PATCH: u32 = 0x4100_0000;
const FLAG_CUMULATIVE_PATCH: u32 = 0x6000_0000;

const FLAG_NAMES: &[(u32, &str)] = &[
    (FLAG_FIRST_PATCH, "FIRST_PATCH"),
    (FLAG_PATCHGO, "PATCHGO"),
    (FLAG_REMASTER, "REMASTER"),
    (FLAG_PS_CLOUD, "PS_CLOUD"),
    (FLAG_GD_AC, "GD_AC"),
    (FLAG_NON_GAME, "NON_GAME"),
    (FLAG_UNKNOWN_0X8000000, "UNKNOWN_0x8000000"),
    (FLAG_SUBSEQUENT_PATCH, "SUBSEQUENT_PATCH"),
    (FLAG_DELTA_PATCH, "DELTA_PATCH"),
    (FLAG_CUMULATIVE_PATCH, "CUMULATIVE_PATCH"),
];

#[derive(Debug, Clone)]
pub struct PkgHeader {
    pub magic: u32,
    pub pkg_type: u32,
    pub pkg_0x8: u32,
    pub pkg_file_count: u32,
    pub pkg_table_entry_count: u32,
    pub pkg_sc_entry_count: u16,
    pub pkg_table_entry_count_2: u16,
    pub pkg_table_entry_offset: u32,
    pub pkg_sc_entry_data_size: u32,
    pub pkg_body_offset: u64,
    pub pkg_body_size: u64,
    pub pkg_content_offset: u64,
    pub pkg_content_size: u64,
    pub pkg_content_id: [u8; 0x24],
    pub pkg_drm_type: u32,
    pub pkg_content_type: u32,
    pub pkg_content_flags: u32,
    pub pfs_image_count: u32,
    pub pfs_image_flags: u64,
    pub pfs_image_offset: u64,
    pub pfs_image_size: u64,
    pub mount_image_offset: u64,
    pub mount_image_size: u64,
    pub pkg_size: u64,
    pub pfs_signed_size: u32,
    pub pfs_cache_size: u32,
}

impl PkgHeader {
    pub fn read_from<R: Read + Seek>(r: &mut R) -> Result<Self> {
        let mut hdr_buf = vec![0u8; 0x440];
        r.seek(SeekFrom::Start(0))?;
        r.read_exact(&mut hdr_buf)
            .context("Failed to read PKG header (0x440 bytes)")?;

        let mut c = Cursor::new(&hdr_buf[..]);
        let magic = c.read_u32::<BigEndian>()?;
        if magic != PKG_MAGIC {
            bail!(
                "Invalid PKG magic: 0x{:08X} (expected 0x{:08X})",
                magic,
                PKG_MAGIC
            );
        }
        let pkg_type = c.read_u32::<BigEndian>()?;
        let pkg_0x8 = c.read_u32::<BigEndian>()?;
        let pkg_file_count = c.read_u32::<BigEndian>()?;
        let pkg_table_entry_count = c.read_u32::<BigEndian>()?;
        let pkg_sc_entry_count = c.read_u16::<BigEndian>()?;
        let pkg_table_entry_count_2 = c.read_u16::<BigEndian>()?;
        let pkg_table_entry_offset = c.read_u32::<BigEndian>()?;
        let pkg_sc_entry_data_size = c.read_u32::<BigEndian>()?;
        let pkg_body_offset = c.read_u64::<BigEndian>()?;
        let pkg_body_size = c.read_u64::<BigEndian>()?;
        let pkg_content_offset = c.read_u64::<BigEndian>()?;
        let pkg_content_size = c.read_u64::<BigEndian>()?;

        let mut pkg_content_id = [0u8; 0x24];
        c.read_exact(&mut pkg_content_id)?;

        c.set_position(0x70);
        let pkg_drm_type = c.read_u32::<BigEndian>()?;
        let pkg_content_type = c.read_u32::<BigEndian>()?;
        let pkg_content_flags = c.read_u32::<BigEndian>()?;

        c.set_position(0x404);
        let pfs_image_count = c.read_u32::<BigEndian>()?;
        let pfs_image_flags = c.read_u64::<BigEndian>()?;
        let pfs_image_offset = c.read_u64::<BigEndian>()?;
        let pfs_image_size = c.read_u64::<BigEndian>()?;
        let mount_image_offset = c.read_u64::<BigEndian>()?;
        let mount_image_size = c.read_u64::<BigEndian>()?;
        let pkg_size = c.read_u64::<BigEndian>()?;
        let pfs_signed_size = c.read_u32::<BigEndian>()?;
        let pfs_cache_size = c.read_u32::<BigEndian>()?;

        Ok(Self {
            magic,
            pkg_type,
            pkg_0x8,
            pkg_file_count,
            pkg_table_entry_count,
            pkg_sc_entry_count,
            pkg_table_entry_count_2,
            pkg_table_entry_offset,
            pkg_sc_entry_data_size,
            pkg_body_offset,
            pkg_body_size,
            pkg_content_offset,
            pkg_content_size,
            pkg_content_id,
            pkg_drm_type,
            pkg_content_type,
            pkg_content_flags,
            pfs_image_count,
            pfs_image_flags,
            pfs_image_offset,
            pfs_image_size,
            mount_image_offset,
            mount_image_size,
            pkg_size,
            pfs_signed_size,
            pfs_cache_size,
        })
    }

    pub fn content_id_str(&self) -> String {
        let end = self
            .pkg_content_id
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.pkg_content_id.len());
        String::from_utf8_lossy(&self.pkg_content_id[..end]).into_owned()
    }

    pub fn header_title_id(&self) -> String {
        if self.pkg_content_id.len() >= 16 {
            String::from_utf8_lossy(&self.pkg_content_id[7..16]).into_owned()
        } else {
            String::new()
        }
    }

    pub fn flags_string(&self) -> String {
        let mut out = Vec::new();
        for &(mask, name) in FLAG_NAMES {
            if (self.pkg_content_flags & mask) != 0 {
                out.push(name);
            }
        }
        out.join(", ")
    }

    pub fn is_patch(&self) -> bool {
        self.flags_string().contains("PATCH")
    }

    pub fn has_pfs_image(&self) -> bool {
        self.pfs_image_count > 0 && self.pfs_cache_size > 0 && self.pfs_image_size > 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PkgEntry {
    pub id: u32,
    pub filename_offset: u32,
    pub flags1: u32,
    pub flags2: u32,
    pub offset: u32,
    pub size: u32,
    pub padding: u64,
    pub raw_bytes: [u8; 32],
}

impl PkgEntry {
    pub fn from_bytes(raw: [u8; 32]) -> Result<Self> {
        let mut c = Cursor::new(&raw[..]);
        Ok(Self {
            id: c.read_u32::<BigEndian>()?,
            filename_offset: c.read_u32::<BigEndian>()?,
            flags1: c.read_u32::<BigEndian>()?,
            flags2: c.read_u32::<BigEndian>()?,
            offset: c.read_u32::<BigEndian>()?,
            size: c.read_u32::<BigEndian>()?,
            padding: c.read_u64::<BigEndian>()?,
            raw_bytes: raw,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PkgKind {
    BaseGame {
        title_id: String,
    },
    Patch {
        title_id: String,
    },
    Dlc {
        title_id: String,
        entitlement_label: String,
        has_pfs_data: bool,
    },
}

impl PkgKind {
    pub fn description(&self) -> &'static str {
        match self {
            PkgKind::BaseGame { .. } => "Base Game",
            PkgKind::Patch { .. } => "Game Update / Patch",
            PkgKind::Dlc {
                has_pfs_data: true, ..
            } => "DLC (with data)",
            PkgKind::Dlc {
                has_pfs_data: false,
                ..
            } => "DLC (entitlement unlock)",
        }
    }

    /// Computes the output folder path under `output_root` matching ShadPS4's layout:
    /// - DLC: `<output_root>/addcont/<TITLE_ID>/<ENTITLEMENT_LABEL>`
    /// - Patch: `<output_root>/games/<TITLE_ID>-patch`
    /// - Base Game: `<output_root>/games/<TITLE_ID>`
    pub fn target_dir(&self, output_root: &Path) -> PathBuf {
        match self {
            PkgKind::BaseGame { title_id } => output_root.join("games").join(title_id),
            PkgKind::Patch { title_id } => {
                output_root.join("games").join(format!("{}-patch", title_id))
            }
            PkgKind::Dlc {
                title_id,
                entitlement_label,
                ..
            } => output_root
                .join("addcont")
                .join(title_id)
                .join(entitlement_label),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PkgMetadata {
    pub header: PkgHeader,
    pub entries: Vec<PkgEntry>,
    pub psf: Psf,
    pub kind: PkgKind,
    pub file_size: u64,
}

impl PkgMetadata {
    pub fn open(path: &Path) -> Result<Self> {
        let mut file =
            File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
        let file_size = file.metadata()?.len();
        let header = PkgHeader::read_from(&mut file)?;

        file.seek(SeekFrom::Start(header.pkg_table_entry_offset as u64))
            .context("Failed to seek to PKG table entry offset")?;

        let n_files = header.pkg_table_entry_count as usize;
        let mut entries = Vec::with_capacity(n_files);
        let mut sfo_entry: Option<PkgEntry> = None;

        for _ in 0..n_files {
            let mut raw = [0u8; 32];
            file.read_exact(&mut raw)?;
            let entry = PkgEntry::from_bytes(raw)?;
            if entry.id == 0x1000 {
                sfo_entry = Some(entry);
            }
            entries.push(entry);
        }

        let sfo_entry = sfo_entry.context("PKG does not contain a param.sfo (0x1000) entry")?;
        file.seek(SeekFrom::Start(sfo_entry.offset as u64))
            .context("Failed to seek to param.sfo offset")?;
        let mut sfo_bytes = vec![0u8; sfo_entry.size as usize];
        file.read_exact(&mut sfo_bytes)
            .context("Failed to read param.sfo bytes")?;

        let psf = Psf::from_bytes(&sfo_bytes).context("Failed to parse param.sfo")?;

        let title_id = psf
            .title_id()
            .map(|s| s.to_string())
            .unwrap_or_else(|| header.header_title_id());

        let category = psf.category().unwrap_or("");
        let kind = if header.is_patch() || category == "gp" {
            PkgKind::Patch { title_id }
        } else if category == "ac" {
            let content_id = psf
                .content_id()
                .map(|s| s.to_string())
                .unwrap_or_else(|| header.content_id_str());
            let entitlement_label = content_id
                .split('-')
                .nth(2)
                .map(|s| s.to_string())
                .or_else(|| {
                    if content_id.len() > 20 {
                        Some(content_id[20..].to_string())
                    } else {
                        None
                    }
                })
                .context("DLC param.sfo is missing a valid CONTENT_ID entitlement label")?;

            PkgKind::Dlc {
                title_id,
                entitlement_label,
                has_pfs_data: header.has_pfs_image(),
            }
        } else {
            PkgKind::BaseGame { title_id }
        };

        Ok(Self {
            header,
            entries,
            psf,
            kind,
            file_size,
        })
    }

    /// Extracts the PKG (both `sce_sys/*` entries and any PFS image files) into `extract_path`.
    /// Returns the number of extracted files (`sce_sys` files + PFS files).
    pub fn extract(&self, pkg_path: &Path, extract_path: &Path) -> Result<usize> {
        let mut file = File::open(pkg_path)
            .with_context(|| format!("Failed to open {}", pkg_path.display()))?;

        if self.header.pkg_size > 0 && self.header.pkg_size > self.file_size {
            bail!(
                "PKG header size ({}) is larger than actual file size ({})",
                self.header.pkg_size,
                self.file_size
            );
        }
        if self.header.pkg_size > 0
            && (self.header.pkg_content_size + self.header.pkg_content_offset)
                > self.header.pkg_size
        {
            bail!("PKG content size + offset exceeds PKG size");
        }

        let sce_sys_dir = extract_path.join("sce_sys");
        fs::create_dir_all(&sce_sys_dir)?;

        let mut dk3 = [0u8; 32];
        let mut iv_key = [0u8; 32];
        let mut img_key = [0u8; 256];
        let mut ekpfs_key = [0u8; 32];
        let mut extracted_count = 0usize;

        for entry in &self.entries {
            let rel_name =
                get_entry_name_by_type(entry.id).unwrap_or_else(|| entry.id.to_string());
            let out_filepath = sce_sys_dir.join(&rel_name);
            if let Some(parent) = out_filepath.parent() {
                fs::create_dir_all(parent)?;
            }

            if entry.id == 0x0010 && entry.size >= 32 + 7 * 32 + 4 * 256 {
                // ENTRY_KEYS: seed_digest (32) + digest1[7] (224) + key1[7] (7 * 256)
                let key3_offset = entry.offset as u64 + 32 + 7 * 32 + 3 * 256;
                file.seek(SeekFrom::Start(key3_offset))?;
                let mut key1_3 = [0u8; 256];
                file.read_exact(&mut key1_3)?;
                rsa2048_decrypt(&mut dk3, &key1_3, true);
            } else if entry.id == 0x0020 && entry.size >= 256 {
                // IMAGE_KEY
                file.seek(SeekFrom::Start(entry.offset as u64))?;
                let mut imgkeydata = [0u8; 256];
                file.read_exact(&mut imgkeydata)?;

                let mut concat = [0u8; 64];
                concat[0..32].copy_from_slice(&entry.raw_bytes);
                concat[32..64].copy_from_slice(&dk3);

                iv_key_hash256(&concat, &mut iv_key);
                aes_cbc_decrypt(&iv_key, &imgkeydata, &mut img_key);
                rsa2048_decrypt(&mut ekpfs_key, &img_key, false);
            }

            // Read raw entry bytes
            file.seek(SeekFrom::Start(entry.offset as u64))?;
            let rsize = entry.size as usize;

            if matches!(entry.id, 0x0400..=0x0403) && rsize > 0 {
                // Decrypt NP entries (license.dat, license.info, nptitle.dat, npbind.dat)
                let msize = if rsize % 16 != 0 {
                    rsize + (16 - (rsize % 16))
                } else {
                    rsize
                };
                let mut cipher_np = vec![0u8; msize];
                file.read_exact(&mut cipher_np[..rsize])?;

                let mut dec_np = vec![0u8; msize];
                let mut concat = [0u8; 64];
                concat[0..32].copy_from_slice(&entry.raw_bytes);
                concat[32..64].copy_from_slice(&dk3);

                iv_key_hash256(&concat, &mut iv_key);
                aes_cbc_decrypt(&iv_key, &cipher_np, &mut dec_np);

                fs::write(&out_filepath, &dec_np[..rsize])?;
            } else {
                let mut data = vec![0u8; rsize];
                file.read_exact(&mut data)?;
                fs::write(&out_filepath, &data)?;
            }
            extracted_count += 1;
        }

        // If this is an entitlement-only DLC (no PFS image), we are done!
        if !self.header.has_pfs_image() {
            return Ok(extracted_count);
        }

        // Otherwise, decrypt and unpack the external PFS image
        let seed_offset = self.header.pfs_image_offset + 0x370;
        if seed_offset + 16 > self.file_size {
            bail!("PFS seed offset out of bounds");
        }
        file.seek(SeekFrom::Start(seed_offset))?;
        let mut seed = [0u8; 16];
        file.read_exact(&mut seed)?;

        let mut data_key = [0u8; 16];
        let mut tweak_key = [0u8; 16];
        pfs_gen_crypto_key(&ekpfs_key, &seed, &mut data_key, &mut tweak_key);

        let length = (self.header.pfs_cache_size as usize) * 2;
        if length == 0 {
            return Ok(extracted_count);
        }

        let mut pfs_encrypted = vec![0u8; length];
        file.seek(SeekFrom::Start(self.header.pfs_image_offset))?;
        file.read_exact(&mut pfs_encrypted)?;

        let mut pfs_decrypted = vec![0u8; length];
        decrypt_pfs(&data_key, &tweak_key, &pfs_encrypted, &mut pfs_decrypted, 0);

        let pfsc_offset = get_pfsc_offset(&pfs_decrypted)
            .context("Could not find PFSC magic in decrypted PFS image")?;
        let pfsc = &pfs_decrypted[pfsc_offset..];

        let pfs_chdr = PfsChdr::from_bytes(pfsc)?;
        if pfs_chdr.block_sz2 <= 0 {
            bail!("Invalid PFSC block_sz2: {}", pfs_chdr.block_sz2);
        }
        let num_blocks = (pfs_chdr.data_length / pfs_chdr.block_sz2) as usize;
        let mut sector_map = Vec::with_capacity(num_blocks + 1);
        let offsets_start = pfs_chdr.block_offsets as usize;
        let mut map_cursor = Cursor::new(&pfsc[offsets_start..]);
        for _ in 0..=num_blocks {
            sector_map.push(map_cursor.read_u64::<LittleEndian>()?);
        }

        let mut ndinode = 0u32;
        let mut ndinode_counter = 0usize;
        let mut dinode_reached = false;
        let mut uroot_reached = false;
        let mut inode_buf: Vec<Inode> = Vec::new();
        let mut fs_table: Vec<PfsFsEntry> = Vec::new();
        let mut extract_paths: HashMap<usize, PathBuf> = HashMap::new();
        let mut current_dir = PathBuf::new();
        let mut decompressed_data = vec![0u8; 0x10000];

        for i in 0..num_blocks {
            let sector_offset = sector_map[i] as usize;
            let sector_size = (sector_map[i + 1] - sector_map[i]) as usize;
            if sector_offset + sector_size > pfsc.len() {
                bail!("PFSC metadata sector {} out of bounds inside cache", i);
            }
            let compressed_slice = &pfsc[sector_offset..sector_offset + sector_size];
            if sector_size == 0x10000 {
                decompressed_data.copy_from_slice(compressed_slice);
            } else if sector_size < 0x10000 {
                decompress_pfsc(compressed_slice, &mut decompressed_data)?;
            }

            if i == 0 {
                ndinode = u32::from_le_bytes(decompressed_data[0x30..0x34].try_into().unwrap());
            }

            let mut occupied_blocks = ((ndinode as usize) * 0xA8) / 0x10000;
            if ((ndinode as usize) * 0xA8) % 0x10000 != 0 {
                occupied_blocks += 1;
            }

            if i >= 1 && i <= occupied_blocks {
                let mut p = 0usize;
                while p + 0xA8 <= 0x10000 {
                    let node = Inode::from_bytes(&decompressed_data[p..p + 0xA8])?;
                    if node.mode == 0 {
                        break;
                    }
                    inode_buf.push(node);
                    p += 0xA8;
                }
            }

            if &decompressed_data[0x10..0x1F] == b"flat_path_table" {
                uroot_reached = true;
            }

            if uroot_reached {
                let mut k = 0usize;
                while k + 16 <= 0x10000 {
                    let dirent = Dirent::from_bytes(&decompressed_data[k..])?;
                    if dirent.ino != 0 {
                        ndinode_counter += 1;
                    } else {
                        extract_paths.insert(ndinode_counter, extract_path.to_path_buf());
                        uroot_reached = false;
                        break;
                    }
                    if dirent.entsize == 0 {
                        break;
                    }
                    k += dirent.entsize as usize;
                }
            }

            let dot = decompressed_data[0x10];
            let dotdot = &decompressed_data[0x28..0x2A];
            if dot == b'.' && dotdot == b".." {
                dinode_reached = true;
            }

            let mut end_reached = false;
            if dinode_reached {
                let mut j = 0usize;
                while j + 16 <= 0x10000 {
                    let dirent = Dirent::from_bytes(&decompressed_data[j..])?;
                    if dirent.ino == 0 {
                        break;
                    }
                    let ino = dirent.ino as usize;
                    let dtype = dirent.dtype;
                    let name = dirent.name.clone();

                    if dtype == PFS_CURRENT_DIR {
                        if let Some(p) = extract_paths.get(&ino) {
                            current_dir = p.clone();
                        }
                    }

                    if dtype == PFS_FILE || dtype == PFS_DIR {
                        let target_p = current_dir.join(&name);
                        extract_paths.insert(ino, target_p.clone());

                        fs_table.push(PfsFsEntry {
                            name,
                            inode: ino,
                            ftype: dtype,
                        });

                        if dtype == PFS_DIR {
                            fs::create_dir_all(&target_p)?;
                        }
                        ndinode_counter += 1;
                        if (ndinode_counter + 1) == ndinode as usize {
                            end_reached = true;
                        }
                    }

                    if dirent.entsize == 0 {
                        break;
                    }
                    j += dirent.entsize as usize;
                }
                if end_reached {
                    break;
                }
            }
        }

        // Filter to PFS_FILE entries and count total 64 KiB blocks for progress reporting
        let file_entries: Vec<&PfsFsEntry> = fs_table
            .iter()
            .filter(|e| e.ftype == PFS_FILE)
            .collect();

        let total_blocks: u64 = file_entries
            .iter()
            .map(|e| inode_buf[e.inode].blocks as u64)
            .sum();

        let file_pb = if total_blocks > 64 {
            let pb = indicatif::ProgressBar::new(total_blocks * 0x10000);
            pb.set_style(
                indicatif::ProgressStyle::with_template(
                    "  {spinner:.cyan} [{elapsed_precise}] [{wide_bar:.green/white}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta}) {msg}",
                )
                .unwrap()
                .progress_chars("=>-"),
            );
            Some(pb)
        } else {
            None
        };

        // Extract all PFS_FILE entries in parallel using pread (read_at)
        use rayon::prelude::*;
        use std::os::unix::fs::FileExt;

        let pfs_image_offset = self.header.pfs_image_offset;
        let file_size = self.file_size;

        file_entries.par_iter().try_for_each(|entry| -> Result<()> {
            let inode = &inode_buf[entry.inode];
            let sector_loc = inode.loc as usize;
            let nblocks = inode.blocks as usize;
            let bsize = inode.size as usize;

            let out_path = extract_paths
                .get(&entry.inode)
                .context("Missing extract path for inode")?;
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }
            if let Some(ref pb) = file_pb {
                pb.set_message(entry.name.clone());
            }

            let out_file = File::create(out_path)?;
            let mut writer = BufWriter::with_capacity(256 * 1024, out_file);

            let pfsc_buf_size = 0x11000usize;
            let mut pfsc_buf = vec![0u8; pfsc_buf_size];
            let mut pfs_dec_buf = vec![0u8; pfsc_buf_size];
            let mut decomp_buf = vec![0u8; 0x10000];
            let mut size_decompressed = 0usize;

            for j in 0..nblocks {
                let sector_offset = sector_map[sector_loc + j];
                let sector_size = (sector_map[sector_loc + j + 1] - sector_offset) as usize;
                let file_offset = pfs_image_offset + (pfsc_offset as u64) + sector_offset;
                let current_sector1 = ((pfsc_offset as u64) + sector_offset) / 0x1000;

                let sector_offset_mask = (sector_offset + pfsc_offset as u64) & !0xFFF;
                let previous_data =
                    ((sector_offset + pfsc_offset as u64) - sector_offset_mask) as usize;

                let read_pos = file_offset - previous_data as u64;
                let read_len = pfsc_buf_size.min((file_size.saturating_sub(read_pos)) as usize);
                pfsc_buf.fill(0);
                file.read_exact_at(&mut pfsc_buf[..read_len], read_pos)?;

                decrypt_pfs(
                    &data_key,
                    &tweak_key,
                    &pfsc_buf,
                    &mut pfs_dec_buf,
                    current_sector1,
                );

                let compressed_slice = &pfs_dec_buf[previous_data..previous_data + sector_size];
                if sector_size == 0x10000 {
                    decomp_buf.copy_from_slice(compressed_slice);
                } else if sector_size < 0x10000 {
                    decompress_pfsc(compressed_slice, &mut decomp_buf)?;
                }

                size_decompressed += 0x10000;

                if j < nblocks - 1 {
                    writer.write_all(&decomp_buf)?;
                } else {
                    let write_size =
                        0x10000usize.saturating_sub(size_decompressed.saturating_sub(bsize));
                    writer.write_all(&decomp_buf[..write_size])?;
                }

                if let Some(ref pb) = file_pb {
                    pb.inc(0x10000);
                }
            }
            writer.flush()?;
            Ok(())
        })?;

        if let Some(pb) = file_pb {
            pb.finish_and_clear();
        }

        extracted_count += file_entries.len();
        Ok(extracted_count)
    }
}
