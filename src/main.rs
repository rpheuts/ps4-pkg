#![allow(dead_code)]

mod crypto;
mod pfs;
mod pkg;
mod pkg_type;
mod psf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use pkg::{PkgKind, PkgMetadata};
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use walkdir::WalkDir;

#[derive(Parser)]
#[command(
    name = "ps4-pkg-installer",
    version,
    about = "Fast PS4 PKG & DLC batch extractor for ShadPS4"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect a single .pkg file or summarize a directory of .pkg files
    Info {
        /// Path to a .pkg file or a directory containing .pkg files
        path: PathBuf,
    },
    /// Extract a .pkg file or recursively extract all .pkg files in a directory into ShadPS4's folder structure
    Extract {
        /// Path to a .pkg file or a directory containing .pkg files
        input: PathBuf,

        /// Output root directory (will create addcont/<TITLE_ID>/<ENTITLEMENT_LABEL> for DLCs, games/<TITLE_ID> for games/patches)
        #[arg(short, long, default_value = "./extracted")]
        output: PathBuf,
    },
}

fn discover_pkg_files(root: &Path) -> Result<Vec<PathBuf>> {
    if root.is_file() {
        return Ok(vec![root.to_path_buf()]);
    }
    if !root.exists() {
        bail!("Input path does not exist: {}", root.display());
    }

    let mut files = Vec::new();
    for entry in WalkDir::new(root).follow_links(true) {
        let entry = entry?;
        if entry.file_type().is_file() {
            if let Some(ext) = entry.path().extension() {
                if ext.eq_ignore_ascii_case("pkg") {
                    files.push(entry.into_path());
                }
            }
        }
    }
    files.sort();
    Ok(files)
}

fn cmd_info(path: &Path) -> Result<()> {
    let files = discover_pkg_files(path)?;
    if files.is_empty() {
        bail!("No .pkg files found in {}", path.display());
    }

    if files.len() == 1 {
        let pkg_path = &files[0];
        let meta = PkgMetadata::open(pkg_path)?;
        println!("File:              {}", pkg_path.display());
        println!("File Size:         {} bytes", meta.file_size);
        println!(
            "Title:             {}",
            meta.psf.title().unwrap_or("<unknown>").trim()
        );
        println!(
            "Title ID:          {}",
            meta.psf
                .title_id()
                .unwrap_or(&meta.header.header_title_id())
        );
        println!(
            "Content ID:        {}",
            meta.psf
                .content_id()
                .unwrap_or(&meta.header.content_id_str())
        );
        if let Some(ent) = meta.psf.entitlement_label() {
            println!("Entitlement Label: {}", ent);
        }
        println!(
            "Category (SFO):    {}",
            meta.psf.category().unwrap_or("<none>")
        );
        println!("Package Type:      {}", meta.kind.description());
        println!(
            "Version:           {}",
            meta.psf.app_ver().unwrap_or("<none>")
        );
        println!("Table Entries:     {}", meta.entries.len());
        println!(
            "Has PFS Image:     {} (pfs_count={}, cache_size=0x{:X})",
            meta.header.has_pfs_image(),
            meta.header.pfs_image_count,
            meta.header.pfs_cache_size
        );
        println!(
            "ShadPS4 Subpath:   {}",
            meta.kind.target_dir(Path::new("<shadps4>")).display()
        );
        return Ok(());
    }

    println!(
        "Scanning {} .pkg files in {}...",
        files.len(),
        path.display()
    );
    let results: Vec<(PathBuf, Result<PkgMetadata>)> = files
        .par_iter()
        .map(|p| (p.clone(), PkgMetadata::open(p)))
        .collect();

    let mut by_title_id: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_type: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut unique_targets: BTreeSet<PathBuf> = BTreeSet::new();
    let mut duplicate_count = 0usize;
    let mut errors = Vec::new();

    for (p, res) in results {
        match res {
            Ok(meta) => {
                let tid = meta
                    .psf
                    .title_id()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| meta.header.header_title_id());
                *by_title_id.entry(tid).or_insert(0) += 1;
                *by_type.entry(meta.kind.description()).or_insert(0) += 1;
                let target = meta.kind.target_dir(Path::new(""));
                if !unique_targets.insert(target) {
                    duplicate_count += 1;
                }
            }
            Err(e) => {
                errors.push((p, e));
            }
        }
    }

    println!("\n=== Summary ===");
    println!("Total .pkg files:       {}", files.len());
    println!("Unique targets:         {}", unique_targets.len());
    if duplicate_count > 0 {
        println!(
            "Duplicate PKGs:         {} (same Title ID & Entitlement Label)",
            duplicate_count
        );
    }
    println!("\nBy Title ID:");
    for (tid, cnt) in &by_title_id {
        println!("  {}: {} package(s)", tid, cnt);
    }
    println!("\nBy Package Type:");
    for (kind, cnt) in &by_type {
        println!("  {}: {}", kind, cnt);
    }

    if !errors.is_empty() {
        println!("\nErrors ({}):", errors.len());
        for (p, e) in errors.iter().take(10) {
            println!("  {}: {:#}", p.display(), e);
        }
    }

    Ok(())
}

fn cmd_extract(input: &Path, output: &Path) -> Result<()> {
    let start = Instant::now();
    let files = discover_pkg_files(input)?;
    if files.is_empty() {
        bail!("No .pkg files found in {}", input.display());
    }

    println!(
        "Found {} .pkg file(s). Parsing headers & metadata...",
        files.len()
    );

    let parsed: Vec<(PathBuf, Result<PkgMetadata>)> = files
        .par_iter()
        .map(|p| (p.clone(), PkgMetadata::open(p)))
        .collect();

    // Deduplicate by target output directory so parallel workers never race on identical DLCs
    let mut jobs: Vec<(PathBuf, PkgMetadata, PathBuf)> = Vec::with_capacity(parsed.len());
    let mut seen_targets: BTreeSet<PathBuf> = BTreeSet::new();
    let mut skipped_duplicates = 0usize;
    let mut parse_errors: Vec<(PathBuf, anyhow::Error)> = Vec::new();

    for (path, res) in parsed {
        match res {
            Ok(meta) => {
                let target_dir = meta.kind.target_dir(output);
                if seen_targets.insert(target_dir.clone()) {
                    jobs.push((path, meta, target_dir));
                } else {
                    skipped_duplicates += 1;
                }
            }
            Err(e) => parse_errors.push((path, e)),
        }
    }

    if skipped_duplicates > 0 {
        println!(
            "Skipping {} duplicate .pkg file(s) with identical target paths.",
            skipped_duplicates
        );
    }

    println!(
        "Extracting {} unique package(s) into {}...",
        jobs.len(),
        output.display()
    );

    let pb = ProgressBar::new(jobs.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta}) {msg}",
        )?
        .progress_chars("#>-"),
    );

    let total_files_extracted = AtomicUsize::new(0);
    let extract_errors: Mutex<Vec<(PathBuf, anyhow::Error)>> = Mutex::new(Vec::new());
    let dlc_title_ids: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
    let game_title_ids: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

    jobs.par_iter().for_each(|(pkg_path, meta, target_dir)| {
        match meta.extract(pkg_path, target_dir) {
            Ok(n) => {
                total_files_extracted.fetch_add(n, Ordering::Relaxed);
                match &meta.kind {
                    PkgKind::Dlc { title_id, .. } => {
                        dlc_title_ids.lock().unwrap().insert(title_id.clone());
                    }
                    PkgKind::BaseGame { title_id } => {
                        game_title_ids.lock().unwrap().insert(title_id.clone());
                    }
                    PkgKind::Patch { title_id } => {
                        game_title_ids
                            .lock()
                            .unwrap()
                            .insert(format!("{}-patch", title_id));
                    }
                }
            }
            Err(e) => {
                extract_errors.lock().unwrap().push((pkg_path.clone(), e));
            }
        }
        pb.inc(1);
    });

    pb.finish_with_message("Done");

    let elapsed = start.elapsed();
    let extract_errors = extract_errors.into_inner().unwrap();
    let dlc_title_ids = dlc_title_ids.into_inner().unwrap();
    let game_title_ids = game_title_ids.into_inner().unwrap();

    println!("\n=== Extraction Complete in {:.2?} ===", elapsed);
    println!(
        "Packages extracted:     {}/{}",
        jobs.len() - extract_errors.len(),
        jobs.len()
    );
    println!(
        "Total files written:    {}",
        total_files_extracted.load(Ordering::Relaxed)
    );

    if !dlc_title_ids.is_empty() {
        println!("\nDLCs ready for ShadPS4:");
        for tid in &dlc_title_ids {
            let dlc_folder = output.join("addcont").join(tid);
            println!(
                "  -> Move '{}' into your ShadPS4 'user/addcont/' folder (so it becomes user/addcont/{})",
                dlc_folder.display(),
                tid
            );
        }
    }

    if !game_title_ids.is_empty() {
        println!("\nGames / Patches ready for ShadPS4:");
        for tid in &game_title_ids {
            let game_folder = output.join("games").join(tid);
            println!(
                "  -> Move '{}' into your ShadPS4 games folder",
                game_folder.display()
            );
        }
    }

    if !parse_errors.is_empty() || !extract_errors.is_empty() {
        println!(
            "\nWarnings/Errors: {} parse error(s), {} extract error(s)",
            parse_errors.len(),
            extract_errors.len()
        );
        for (p, e) in parse_errors.iter().chain(extract_errors.iter()).take(10) {
            println!("  {}: {:#}", p.display(), e);
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Info { path } => cmd_info(path),
        Commands::Extract { input, output } => cmd_extract(input, output),
    }
}
