use super::*;
use std::io::Cursor;

fn package() -> Package {
    Package {
        url: "https://example.invalid/package.tar.zst".into(),
        sha256: format!("{:x}", Sha256::digest(b"expected")),
        static_archive_sha256: BTreeMap::new(),
    }
}

#[test]
fn missing_or_changed_packages_fail_offline() {
    let cache = tempfile::tempdir().unwrap();
    let package = package();
    assert!(
        checked_download(&package, cache.path(), true)
            .unwrap_err()
            .to_string()
            .contains("missing cached Windows package")
    );
    fs::write(cache.path().join("package.tar.zst"), b"changed").unwrap();
    assert!(
        checked_download(&package, cache.path(), true)
            .unwrap_err()
            .to_string()
            .contains("cached package checksum mismatch")
    );
    assert_eq!(
        fs::read(cache.path().join("package.tar.zst")).unwrap(),
        b"changed"
    );
}

#[test]
fn unsafe_paths_and_links_are_rejected() {
    for name in [
        "../escape",
        "/absolute",
        "mingw64/../../escape",
        "C:/escape",
        "mingw64\\escape",
        "mingw64/.. /escape",
        "mingw64/include./escape",
    ] {
        assert!(safe_member(name).is_err(), "{name}");
    }
    let directory = tempfile::tempdir().unwrap();
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    tar.append_link(&mut header, "mingw64/include", "../../escape")
        .unwrap();
    let bytes = tar.into_inner().unwrap();
    assert!(
        extract_package(Cursor::new(bytes), directory.path())
            .unwrap_err()
            .to_string()
            .contains("unsupported Windows package member type")
    );
    assert!(!directory.path().join("mingw64").exists());
}

#[test]
fn prepared_tree_rejects_changed_headers_and_manifests() {
    let directory = tempfile::tempdir().unwrap();
    let manifest = directory.path().join("manifest.json");
    fs::write(
        &manifest,
        serde_json::json!({
            "target": "x86_64-pc-windows-gnu",
            "packages": [{"url": "https://example.invalid/package.tar.zst",
                "sha256": "unused", "static_archive_sha256": {}}]
        })
        .to_string(),
    )
    .unwrap();
    let output = directory.path().join("output");
    let prefix = output.join("mingw64");
    fs::create_dir_all(prefix.join("include")).unwrap();
    fs::write(prefix.join("include/regex.h"), b"header").unwrap();
    let report = Prepared {
        manifest_sha256: checksum(&manifest).unwrap(),
        files: tree_hashes(&prefix).unwrap(),
    };
    let marker = output.join("windows-posix-build.json");
    fs::write(&marker, serde_json::to_vec(&report).unwrap()).unwrap();
    fs::write(prefix.join("include/regex.h"), b"modified").unwrap();
    assert!(
        prepare_pinned(&manifest, &output, true)
            .unwrap_err()
            .to_string()
            .contains("prepared Windows POSIX files changed")
    );
    fs::write(prefix.join("include/regex.h"), b"header").unwrap();
    let mut contents = fs::read(&manifest).unwrap();
    contents.push(b'\n');
    fs::write(&manifest, contents).unwrap();
    assert!(
        prepare_pinned(&manifest, &output, true)
            .unwrap_err()
            .to_string()
            .contains("pinned Windows POSIX packages changed")
    );
}

#[test]
fn unmanaged_prefix_is_left_untouched() {
    let directory = tempfile::tempdir().unwrap();
    let manifest = directory.path().join("manifest.json");
    fs::write(
        &manifest,
        serde_json::json!({
            "target": "x86_64-pc-windows-gnu",
            "packages": [{"url": "https://example.invalid/package.tar.zst",
                "sha256": "unused", "static_archive_sha256": {}}]
        })
        .to_string(),
    )
    .unwrap();
    let prefix = directory.path().join("mingw64");
    fs::create_dir(&prefix).unwrap();
    fs::write(prefix.join("keep"), b"user file").unwrap();
    assert!(
        prepare_pinned(&manifest, directory.path(), true)
            .unwrap_err()
            .to_string()
            .contains("unmanaged Windows POSIX prefix")
    );
    assert_eq!(fs::read(prefix.join("keep")).unwrap(), b"user file");
}

#[test]
fn override_accepts_rebuilt_archives_and_requires_headers() {
    let directory = tempfile::tempdir().unwrap();
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
        let file = directory.path().join(name);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, b"locally rebuilt").unwrap();
    }
    validate_override(directory.path()).unwrap();
    fs::remove_file(directory.path().join("include/tre/tre.h")).unwrap();
    assert!(
        validate_override(directory.path())
            .unwrap_err()
            .to_string()
            .contains("tre.h")
    );
}
