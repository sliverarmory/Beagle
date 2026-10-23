//! Prepare the checksum-pinned MinGW POSIX dependencies without external tools.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    time::Duration,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Deserialize)]
struct Manifest {
    target: String,
    packages: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    url: String,
    sha256: String,
    static_archive_sha256: BTreeMap<String, String>,
}

#[derive(Deserialize, Serialize)]
struct Prepared {
    manifest_sha256: String,
    files: BTreeMap<String, String>,
}

pub fn prepare(root: &Path, out: &Path) -> PathBuf {
    for name in ["BEAGLE_WINDOWS_POSIX_ROOT", "CARGO_NET_OFFLINE"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    if let Some(value) = env::var_os("BEAGLE_WINDOWS_POSIX_ROOT") {
        let prefix = root.join(value);
        validate_override(&prefix).unwrap_or_else(|error| {
            panic!(
                "invalid BEAGLE_WINDOWS_POSIX_ROOT {}: {error}",
                prefix.display()
            )
        });
        println!(
            "cargo:rerun-if-changed={}",
            prefix.join("include").display()
        );
        println!("cargo:rerun-if-changed={}", prefix.join("lib").display());
        return prefix;
    }

    let manifest = root.join(".github/build/windows-posix.json");
    println!("cargo:rerun-if-changed={}", manifest.display());
    let output = out.join("windows-posix");
    let offline = env::var("CARGO_NET_OFFLINE").is_ok_and(|value| value == "true" || value == "1");
    let prefix = prepare_pinned(&manifest, &output, offline)
        .unwrap_or_else(|error| panic!("prepare pinned Windows POSIX dependencies: {error}"));
    println!("cargo:rerun-if-changed={}", output.display());
    prefix
}

fn validate_override(prefix: &Path) -> Result<()> {
    // An explicit prefix also supports locally rebuilt LGPL dependencies, so
    // fixed binary checksums apply only to our automatically prepared inputs.
    for name in [
        "include/regex.h",
        "include/tre/regex.h",
        "include/tre/tre.h",
        "include/tre/tre-config.h",
        "lib/libsystre.a",
        "lib/libtre.a",
        "lib/libintl.a",
        "lib/libiconv.a",
    ] {
        let path = prefix.join(name);
        regular_file(&path)?;
        if fs::metadata(&path)?.len() == 0 {
            return Err(format!("empty Windows POSIX input: {}", path.display()).into());
        }
    }
    Ok(())
}

fn prepare_pinned(manifest_path: &Path, output: &Path, offline: bool) -> Result<PathBuf> {
    let contents = fs::read(manifest_path)?;
    let manifest: Manifest = serde_json::from_slice(&contents)?;
    if manifest.target != "x86_64-pc-windows-gnu" || manifest.packages.is_empty() {
        return Err("Windows POSIX manifest must describe x86_64-pc-windows-gnu packages".into());
    }
    let manifest_sha256 = format!("{:x}", Sha256::digest(&contents));
    directory(output)?;
    let prefix = output.join("mingw64");
    let marker = output.join("windows-posix-build.json");
    if exists(&prefix)? {
        regular_file(&marker).map_err(|_| {
            format!(
                "unmanaged Windows POSIX prefix {}; use a fresh Cargo target directory",
                prefix.display()
            )
        })?;
        let previous: Prepared = serde_json::from_slice(&fs::read(&marker)?)?;
        if previous.manifest_sha256 != manifest_sha256 {
            return Err(
                "pinned Windows POSIX packages changed; use a fresh Cargo target directory".into(),
            );
        }
        if tree_hashes(&prefix)? != previous.files {
            return Err(
                "prepared Windows POSIX files changed; use a fresh Cargo target directory".into(),
            );
        }
        verify_archives(&prefix, &manifest)?;
    } else if exists(&marker)? {
        return Err(
            "Windows POSIX marker exists without its prefix; use a fresh Cargo target directory"
                .into(),
        );
    }

    let cache = output.join("packages");
    directory(&cache)?;
    let archives = manifest
        .packages
        .iter()
        .map(|package| checked_download(package, &cache, offline))
        .collect::<Result<Vec<_>>>()?;
    if exists(&prefix)? {
        return Ok(prefix);
    }

    // This directory is ours only after create_dir succeeds. Never delete or
    // overwrite an existing extraction directory, prefix, or cached package.
    let staging = output.join(format!("extract-{}", std::process::id()));
    fs::create_dir(&staging)?;
    let result: Result<PathBuf> = (|| {
        for archive in archives {
            let decoder = ruzstd::decoding::StreamingDecoder::new(File::open(&archive)?)
                .map_err(|error| format!("decode {}: {error}", archive.display()))?;
            extract_package(decoder, &staging)
                .map_err(|error| format!("extract {}: {error}", archive.display()))?;
        }
        let extracted = staging.join("mingw64");
        verify_archives(&extracted, &manifest)?;
        validate_override(&extracted)?;
        let report = Prepared {
            manifest_sha256,
            files: tree_hashes(&extracted)?,
        };
        let staged_marker = staging.join("windows-posix-build.json");
        fs::write(&staged_marker, serde_json::to_vec_pretty(&report)?)?;
        fs::rename(extracted, &prefix)?;
        fs::rename(staged_marker, &marker)?;
        Ok(prefix)
    })();
    let cleanup = fs::remove_dir_all(staging);
    let prefix = result?;
    cleanup?;
    Ok(prefix)
}

fn checked_download(package: &Package, cache: &Path, offline: bool) -> Result<PathBuf> {
    let filename = package.url.rsplit('/').next().unwrap_or_default();
    if !package.url.starts_with("https://")
        || filename.is_empty()
        || filename.contains(['\\', ':', '?', '#'])
        || matches!(filename, "." | "..")
    {
        return Err(format!("invalid pinned Windows package URL: {}", package.url).into());
    }
    let archive = cache.join(filename);
    if exists(&archive)? {
        check_hash(&archive, &package.sha256, "cached package")?;
        return Ok(archive);
    }
    if offline {
        return Err(format!("missing cached Windows package with CARGO_NET_OFFLINE set: {filename}; prepare it online or set BEAGLE_WINDOWS_POSIX_ROOT").into());
    }

    let temporary = cache.join(format!("{filename}.download-{}", std::process::id()));
    let mut downloaded = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    let result: Result<PathBuf> = (|| {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .https_only(true)
            .timeout_global(Some(Duration::from_secs(120)))
            .build()
            .into();
        let mut response = agent
            .get(&package.url)
            .call()
            .map_err(|error| format!("download {}: {error}", package.url))?;
        io::copy(&mut response.body_mut().as_reader(), &mut downloaded)?;
        drop(downloaded);
        check_hash(&temporary, &package.sha256, "downloaded package")?;
        fs::rename(&temporary, &archive)?;
        Ok(archive)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn extract_package(reader: impl Read, staging: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    let mut selected = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = String::from_utf8(entry.path_bytes().into_owned())?;
        let path = safe_member(&name)?;
        let kind = entry.header().entry_type();
        // The pinned packages contain only directories and regular files.
        // Reject all links, including links that would remain inside staging.
        if !kind.is_file() && !kind.is_dir() {
            return Err(format!("unsupported Windows package member type: {name}").into());
        }
        if path
            .components()
            .next()
            .is_none_or(|part| part.as_os_str() != "mingw64")
        {
            continue;
        }
        selected = true;
        let destination = staging.join(path);
        if kind.is_dir() {
            directory(&destination)?;
        } else {
            directory(destination.parent().unwrap())?;
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(destination)?;
            io::copy(&mut entry, &mut file)?;
        }
    }
    if !selected {
        return Err("pinned Windows package has no mingw64 contents".into());
    }
    Ok(())
}

fn safe_member(name: &str) -> Result<PathBuf> {
    let path = name.trim_end_matches('/');
    if path.is_empty()
        || path.starts_with('/')
        || path.contains(['\\', ':'])
        || path
            .split('/')
            .any(|part| part.is_empty() || part.ends_with(['.', ' ']))
    {
        return Err(format!("unsafe Windows package member: {name}").into());
    }
    Ok(PathBuf::from(path))
}

fn verify_archives(prefix: &Path, manifest: &Manifest) -> Result<()> {
    for package in &manifest.packages {
        for (filename, expected) in &package.static_archive_sha256 {
            let path = safe_member(filename)?;
            if path.components().count() != 1 {
                return Err(format!("invalid static archive filename: {filename}").into());
            }
            check_hash(&prefix.join("lib").join(path), expected, "static archive")?;
        }
    }
    Ok(())
}

fn tree_hashes(prefix: &Path) -> Result<BTreeMap<String, String>> {
    fn visit(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.is_dir() {
            for entry in fs::read_dir(path)? {
                visit(root, &entry?.path(), files)?;
            }
        } else if metadata.is_file() {
            let name = path
                .strip_prefix(root)?
                .to_str()
                .ok_or("non-UTF-8 Windows input path")?
                .replace('\\', "/");
            files.insert(name, checksum(path)?);
        } else {
            return Err(format!(
                "unexpected link or special file in Windows POSIX inputs: {}",
                path.display()
            )
            .into());
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    visit(prefix, prefix, &mut files)?;
    Ok(files)
}

fn checksum(path: &Path) -> Result<String> {
    regular_file(path)?;
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn check_hash(path: &Path, expected: &str, description: &str) -> Result<()> {
    if checksum(path)? != expected {
        return Err(format!("{description} checksum mismatch: {}", path.display()).into());
    }
    Ok(())
}

fn regular_file(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file()) {
        return Err(format!(
            "expected regular Windows POSIX input file: {}",
            path.display()
        )
        .into());
    }
    Ok(())
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    if !fs::symlink_metadata(path)?.is_dir() {
        return Err(format!("expected Windows POSIX input directory: {}", path.display()).into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod tests;
