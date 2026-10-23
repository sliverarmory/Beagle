#[path = "build-support/native.rs"]
mod native;
#[path = "build-support/windows.rs"]
mod windows;

use std::{env, path::PathBuf};

fn main() {
    for path in [
        "build.rs",
        "build-support/native.rs",
        "build-support/windows.rs",
        "vendor/build-inputs.json",
        "vendor/graphqlite-source.tar.gz",
        "vendor/graphqlite-source.json",
        ".github/build/windows-posix.json",
        ".github/build/windows_compat.h",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    for name in [
        "BEAGLE_WINDOWS_POSIX_ROOT",
        "BISON",
        "FLEX",
        "BEAGLE_SOURCE_REVISION",
        "BEAGLE_RELEASE_BUILD",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target = env::var("TARGET").unwrap();
    let revision = env::var("BEAGLE_SOURCE_REVISION").unwrap_or_else(|_| "development".into());
    if env::var("BEAGLE_RELEASE_BUILD").as_deref() == Ok("1") {
        assert!(
            revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "release builds require a full BEAGLE_SOURCE_REVISION commit"
        );
    }
    println!("cargo:rustc-env=BEAGLE_BUILD_REVISION={revision}");
    println!("cargo:rustc-env=BEAGLE_BUILD_TARGET={target}");
    assert!(
        matches!(target_os.as_str(), "macos" | "linux") || target == "x86_64-pc-windows-gnu",
        "Beagle's static GraphQLite build supports macOS, Linux, and Windows x64 with the x86_64-pc-windows-gnu target"
    );
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    native::verify_inputs(&root).unwrap_or_else(|error| panic!("invalid build inputs: {error}"));
    let sqlite_headers = PathBuf::from(
        env::var_os("DEP_SQLITE3_INCLUDE")
            .expect("libsqlite3-sys must provide its bundled SQLite headers"),
    );
    let windows_posix = (target_os == "windows").then(|| windows::prepare(&root, &out));
    native::build(&root, &out, &sqlite_headers, windows_posix.as_deref())
        .unwrap_or_else(|error| panic!("static GraphQLite build failed: {error}"));

    if target_os == "linux" {
        println!("cargo:rustc-link-lib=m");
    }
    if let Some(prefix) = windows_posix {
        println!(
            "cargo:rustc-link-search=native={}",
            prefix.join("lib").display()
        );
        for library in ["systre", "tre", "intl", "iconv"] {
            println!("cargo:rustc-link-lib=static={library}");
        }
        // GNU libintl reads Windows locale preferences through the registry.
        println!("cargo:rustc-link-lib=advapi32");
        // Keep MinGW/GCC support libraries in the executable as well. Windows
        // system DLL import libraries remain the normal platform dependencies.
        println!("cargo:rustc-link-arg=-static");
    }
}
