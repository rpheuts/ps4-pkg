# ps4-pkg-installer

A fast, standalone, multi-threaded Rust CLI utility for inspecting and extracting PlayStation 4 Fake PKG (`.pkg`) files—base games, game updates/patches, and DLCs (both data-bearing and entitlement-only)—directly into the folder layout expected by **ShadPS4** (v0.7.0+).

## Features

- **Full PKG & PFS Extraction Pipeline**:
  - Parses `PKGHeader`, `PKGEntry` tables, and `sce_sys/param.sfo` (`PSF`).
  - Decrypts `entry_keys` (`0x0010`), `image_key` (`0x0020`), and NP license files (`0x0400..0x0403` such as `license.dat` / `license.info`) using RSA-2048 (`PkgDerivedKey3Keyset` & `FakeKeyset`), SHA-256, and AES-128-CBC.
  - Unpacks external encrypted/compressed PFS filesystem images (`PFSC`) using HMAC-SHA256 key derivation, AES-128-XTS sector decryption, and `zlib` block decompression.
- **Supports All Package Types**:
  - **Base Games (`gd`)** -> `<output>/games/<TITLE_ID>/`
  - **Game Updates / Patches (`gp` / `PATCH`)** -> `<output>/games/<TITLE_ID>-patch/`
  - **DLCs with Extra Data & Entitlement-Only DLCs (`ac`)** -> `<output>/addcont/<TITLE_ID>/<ENTITLEMENT_LABEL>/`
- **Multi-Threaded Batch Processing**:
  - Point `ps4-pkg-installer` at a single `.pkg` file or a directory containing hundreds/thousands of `.pkg` files.
  - Automatically deduplicates identical target paths and extracts packages in parallel across all CPU cores using `rayon` and zero-seek positional reads (`pread`).

## Building

Requires a standard Rust toolchain (`cargo`):

```bash
cargo build --release
```

The compiled binary will be located at `./target/release/ps4-pkg-installer`.

## Usage

### 1. Inspect a `.pkg` File or Directory

```bash
# Inspect a single .pkg file
./target/release/ps4-pkg-installer info /path/to/file.pkg

# Summarize a directory of .pkg files recursively
./target/release/ps4-pkg-installer info /path/to/pkg_folder
```

### 2. Extract `.pkg` File(s) for ShadPS4

```bash
# Extract a single .pkg or an entire directory of .pkg files (defaults to -o ./extracted)
./target/release/ps4-pkg-installer extract /path/to/pkg_or_folder -o ./extracted
```

### Moving Extracted Files into ShadPS4

After extraction completes:
- **DLCs**: Move `<output>/addcont/<TITLE_ID>` into your ShadPS4 `addcont` directory (e.g., `user/addcont/<TITLE_ID>`).
- **Base Games & Updates**: Move `<output>/games/<TITLE_ID>` (and `<output>/games/<TITLE_ID>-patch` for updates, or merge its contents into `<TITLE_ID>`) into your ShadPS4 games directory.
