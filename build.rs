use std::{
    env,
    ffi::{OsStr, OsString},
    path::PathBuf,
    process::Command,
};

fn supported_python(executable: &OsStr) -> bool {
    Command::new(executable)
        .args([
            "-c",
            "import sys; sys.exit(not ((3, 11) <= sys.version_info[:2] <= (3, 14)))",
        ])
        .status()
        .is_ok_and(|status| status.success())
}

fn python_executable() -> OsString {
    if let Some(executable) = env::var_os("BEAGLE_PYTHON") {
        assert!(
            supported_python(&executable),
            "BEAGLE_PYTHON must name Python 3.11 through 3.14; the pinned angreal helper does not support newer Python versions"
        );
        return executable;
    }
    for candidate in [
        "python3.14",
        "python3.13",
        "python3.12",
        "python3.11",
        "python3",
    ] {
        if supported_python(OsStr::new(candidate)) {
            return candidate.into();
        }
    }
    panic!(
        "Install Python 3.11 through 3.14 or set BEAGLE_PYTHON to a supported interpreter to build the pinned angreal helper"
    );
}

fn strings<'a>(values: impl Iterator<Item = &'a OsStr>) -> Vec<String> {
    values
        .map(|value| {
            value
                .to_str()
                .expect("build tool arguments must be UTF-8")
                .to_owned()
        })
        .collect()
}

fn main() {
    for path in [
        "build.rs",
        "vendor/graphqlite-source.tar.gz",
        "vendor/graphqlite-source.json",
        "tools/build_backend.py",
        "tools/static_backend/task_beagle_static.py",
        "tools/static_backend/Makefile.beagle",
        "tools/static_backend/windows_compat.h",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    for name in [
        "BEAGLE_PYTHON",
        "BEAGLE_ANGREAL",
        "BEAGLE_WINDOWS_POSIX_ROOT",
        "BISON",
        "FLEX",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target = env::var("TARGET").unwrap();
    assert!(
        matches!(target_os.as_str(), "macos" | "linux") || target == "x86_64-pc-windows-gnu",
        "Beagle's static GraphQLite build supports macOS, Linux, and Windows x64 with the x86_64-pc-windows-gnu target"
    );
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let sqlite_headers = env::var_os("DEP_SQLITE3_INCLUDE")
        .expect("libsqlite3-sys must provide its bundled SQLite headers");
    let mut native = cc::Build::new();
    native.pic(true).warnings(false);
    let windows_posix = if target_os == "windows" {
        let prefix = PathBuf::from(env::var_os("BEAGLE_WINDOWS_POSIX_ROOT").expect(
            "Windows builds require BEAGLE_WINDOWS_POSIX_ROOT pointing to the MSYS2 mingw64 prefix with libsystre, libtre, gettext-runtime, and libiconv installed",
        ));
        let include = prefix.join("include");
        assert!(
            include.join("regex.h").is_file(),
            "missing Windows POSIX regex.h"
        );
        // The bundled headers must precede the MSYS2 prefix, which may also
        // contain an unrelated SQLite installation.
        native.include(&sqlite_headers).include(&include);
        native.flag("-include").flag(
            root.join("tools/static_backend/windows_compat.h")
                .to_str()
                .unwrap(),
        );
        for library in ["systre", "tre", "intl", "iconv"] {
            let archive = prefix.join("lib").join(format!("lib{library}.a"));
            assert!(
                archive.is_file(),
                "missing static Windows library: {}",
                archive.display()
            );
            println!("cargo:rerun-if-changed={}", archive.display());
        }
        println!("cargo:rerun-if-changed={}", include.display());
        Some(prefix)
    } else {
        None
    };
    let compiler = native.get_compiler().to_command();
    let archiver = native.get_archiver();
    let compiler_command = std::iter::once(compiler.get_program()).chain(compiler.get_args());
    let archive_command = std::iter::once(archiver.get_program()).chain(archiver.get_args());
    let mut command = Command::new(python_executable());
    command
        .arg(root.join("tools/build_backend.py"))
        .arg("--static")
        .arg("--out-dir")
        .arg(&out)
        .arg("--sqlite-include")
        .arg(sqlite_headers)
        .env(
            "BEAGLE_CC",
            serde_json::to_string(&strings(compiler_command)).unwrap(),
        )
        .env(
            "BEAGLE_AR",
            serde_json::to_string(&strings(archive_command)).unwrap(),
        )
        .env(
            "BEAGLE_BUILD_JOBS",
            env::var("NUM_JOBS").unwrap_or_else(|_| "1".into()),
        );
    for (name, value) in compiler.get_envs().chain(archiver.get_envs()) {
        if let Some(value) = value {
            command.env(name, value);
        } else {
            command.env_remove(name);
        }
    }
    if let Some(angreal) = env::var_os("BEAGLE_ANGREAL") {
        command.arg("--angreal").arg(angreal);
    }
    let status = command
        .status()
        .expect("run Python3 to build the pinned GraphQLite backend");
    assert!(status.success(), "static GraphQLite build failed");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=beagle_graphqlite");
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
