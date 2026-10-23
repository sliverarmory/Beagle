#[allow(dead_code)]
#[path = "../build-support/native.rs"]
mod native;

use flate2::{Compression, write::GzEncoder};
use std::{collections::BTreeMap, fs, path::Path};
use tar::{Builder, EntryType, Header};
use tempfile::TempDir;

const CONTENTS: &[u8] = b"int pinned_source;\n";
const SOURCE: &str = "graphqlite/src/backend.c";

fn inventory() -> BTreeMap<String, String> {
    BTreeMap::from([("src/backend.c".into(), native::checksum(CONTENTS))])
}

fn archive(path: &Path, members: &[(&str, &[u8], EntryType)]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut archive = Builder::new(GzEncoder::new(
        fs::File::create(path).unwrap(),
        Compression::default(),
    ));
    for (name, contents, kind) in members {
        let mut header = Header::new_gnu();
        // Set raw path bytes to exercise rejection of paths that tar::Builder's
        // safe set_path would itself reject (including traversal and drives).
        assert!(name.len() < 100);
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_mode(0o644);
        header.set_entry_type(*kind);
        header.set_size(contents.len() as u64);
        if kind.is_symlink() || kind.is_hard_link() {
            header.set_link_name("../outside").unwrap();
        }
        header.set_cksum();
        archive.append(&header, *contents).unwrap();
    }
    archive.into_inner().unwrap().finish().unwrap();
}

fn pinned_archive(root: &Path) -> std::path::PathBuf {
    let path = root.join("vendor/graphqlite-source.tar.gz");
    archive(&path, &[(SOURCE, CONTENTS, EntryType::Regular)]);
    let manifest = serde_json::json!({
        "base_commit": "test-fixture",
        "files": inventory(),
        "source_archive_sha256": native::checksum(&fs::read(&path).unwrap()),
    });
    fs::write(
        root.join("vendor/graphqlite-source.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    path
}

#[test]
fn rejects_unsafe_or_uninventoried_members() {
    let root = TempDir::new().unwrap();
    let path = root.path().join("source.tar.gz");
    let cases = [
        ("graphqlite/../outside", EntryType::Regular),
        ("/outside", EntryType::Regular),
        ("other/src/backend.c", EntryType::Regular),
        ("graphqlite/C:/outside", EntryType::Regular),
        ("graphqlite/src\\..\\outside", EntryType::Regular),
        (SOURCE, EntryType::Symlink),
        (SOURCE, EntryType::Link),
        (SOURCE, EntryType::Directory),
        ("graphqlite/extra.c", EntryType::Regular),
    ];
    for (index, (name, kind)) in cases.into_iter().enumerate() {
        archive(&path, &[(name, CONTENTS, kind)]);
        let destination = root.path().join(format!("extracted-{index}"));
        assert!(
            native::extract_verified(&path, &destination, &inventory()).is_err(),
            "accepted {name} ({kind:?})"
        );
    }
    assert!(!root.path().join("outside").exists());
}

#[test]
fn rejects_duplicate_missing_and_corrupted_sources() {
    let root = TempDir::new().unwrap();
    let path = root.path().join("source.tar.gz");
    let original = (SOURCE, CONTENTS, EntryType::Regular);
    let cases = [
        (vec![original, original], "duplicate"),
        (vec![], "missing inventoried"),
        (
            vec![(SOURCE, b"changed".as_slice(), EntryType::Regular)],
            "checksum mismatch",
        ),
    ];
    for (index, (members, expected)) in cases.into_iter().enumerate() {
        archive(&path, &members);
        let destination = root.path().join(format!("extracted-{index}"));
        let error = native::extract_verified(&path, &destination, &inventory()).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn fresh_extraction_discards_modified_sources_and_cached_build_artifacts() {
    let root = TempDir::new().unwrap();
    pinned_archive(root.path());
    let output = root.path().join("output");
    let (source, _) = native::pinned_source(root.path(), &output).unwrap();
    let cached_source = source.join("src/backend.c");
    fs::write(&cached_source, b"changed").unwrap();
    let extra = source.join("src/unlisted.c");
    fs::write(&extra, b"int cached_injection;").unwrap();
    let generated = source.join("build/stale.o");
    fs::create_dir_all(generated.parent().unwrap()).unwrap();
    fs::write(&generated, b"stale object").unwrap();
    let (refreshed, _) = native::pinned_source(root.path(), &output).unwrap();
    assert_eq!(refreshed, source);
    assert_eq!(fs::read(cached_source).unwrap(), CONTENTS);
    assert!(!extra.exists());
    assert!(!generated.exists());
}

#[test]
fn checks_archive_digest_before_extraction() {
    let root = TempDir::new().unwrap();
    let path = pinned_archive(root.path());
    let mut changed = fs::read(&path).unwrap();
    changed.extend_from_slice(b"changed archive");
    fs::write(path, changed).unwrap();
    let output = root.path().join("output");
    let error = native::pinned_source(root.path(), &output).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("source archive checksum mismatch")
    );
    assert!(!output.exists());
}

#[test]
fn validates_tracked_catalog_and_rejects_checksum_mismatch() {
    let root = TempDir::new().unwrap();
    fs::create_dir(root.path().join("vendor")).unwrap();
    fs::create_dir(root.path().join("data")).unwrap();
    let catalog = root.path().join("data/queries.json");
    fs::write(&catalog, b"[]").unwrap();
    fs::write(
        root.path().join("vendor/build-inputs.json"),
        serde_json::to_vec(&serde_json::json!({
            "files": {"data/queries.json": native::checksum(b"[]")},
        }))
        .unwrap(),
    )
    .unwrap();
    native::verify_inputs(root.path()).unwrap();
    fs::write(&catalog, b"modified").unwrap();
    let error = native::verify_inputs(root.path()).unwrap_err();
    assert!(error.to_string().contains("build input checksum mismatch"));
}
