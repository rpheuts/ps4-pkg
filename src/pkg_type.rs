/// Maps a PS4 PKG entry ID to its corresponding relative path inside `sce_sys/`.
pub fn get_entry_name_by_type(id: u32) -> Option<String> {
    let s = match id {
        0x0001 => "digests",
        0x0010 => "entry_keys",
        0x0020 => "image_key",
        0x0080 => "general_digests",
        0x0100 => "metas",
        0x0200 => "entry_names",
        0x0400 => "license.dat",
        0x0401 => "license.info",
        0x0402 => "nptitle.dat",
        0x0403 => "npbind.dat",
        0x0404 => "selfinfo.dat",
        0x0406 => "imageinfo.dat",
        0x0407 => "target-deltainfo.dat",
        0x0408 => "origin-deltainfo.dat",
        0x0409 => "psreserved.dat",
        0x1000 => "param.sfo",
        0x1001 => "playgo-chunk.dat",
        0x1002 => "playgo-chunk.sha",
        0x1003 => "playgo-manifest.xml",
        0x1004 => "pronunciation.xml",
        0x1005 => "pronunciation.sig",
        0x1006 => "pic1.png",
        0x1007 => "pubtoolinfo.dat",
        0x1008 => "app/playgo-chunk.dat",
        0x1009 => "app/playgo-chunk.sha",
        0x100A => "app/playgo-manifest.xml",
        0x100B => "shareparam.json",
        0x100C => "shareoverlayimage.png",
        0x100D => "save_data.png",
        0x100E => "shareprivacyguardimage.png",
        0x1200 => "icon0.png",
        0x1201..=0x121F => return Some(format!("icon0_{:02}.png", id - 0x1201)),
        0x1220 => "pic0.png",
        0x1240 => "snd0.at9",
        0x1241..=0x125F => return Some(format!("pic1_{:02}.png", id - 0x1241)),
        0x1260 => "changeinfo/changeinfo.xml",
        0x1261..=0x127F => return Some(format!("changeinfo/changeinfo_{:02}.xml", id - 0x1261)),
        0x1280 => "icon0.dds",
        0x1281..=0x129F => return Some(format!("icon0_{:02}.dds", id - 0x1281)),
        0x12A0 => "pic0.dds",
        0x12C0 => "pic1.dds",
        0x12C1..=0x12DF => return Some(format!("pic1_{:02}.dds", id - 0x12C1)),
        0x1400..=0x1463 => return Some(format!("trophy/trophy{:02}.trp", id - 0x1400)),
        0x1600..=0x1609 => return Some(format!("keymap_rp/{:03}.png", id - 0x1600 + 1)),
        0x1610..=0x17F9 if (id & 0xF) <= 9 => {
            let group = (id - 0x1610) >> 4;
            let idx = (id & 0xF) + 1;
            return Some(format!("keymap_rp/{:02}/{:03}.png", group, idx));
        }
        _ => return None,
    };
    Some(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_names() {
        assert_eq!(get_entry_name_by_type(0x0001).as_deref(), Some("digests"));
        assert_eq!(get_entry_name_by_type(0x0400).as_deref(), Some("license.dat"));
        assert_eq!(get_entry_name_by_type(0x1000).as_deref(), Some("param.sfo"));
        assert_eq!(get_entry_name_by_type(0x1205).as_deref(), Some("icon0_04.png"));
        assert_eq!(
            get_entry_name_by_type(0x1400).as_deref(),
            Some("trophy/trophy00.trp")
        );
        assert_eq!(
            get_entry_name_by_type(0x17F9).as_deref(),
            Some("keymap_rp/30/010.png")
        );
        assert_eq!(get_entry_name_by_type(0x9999), None);
    }
}
