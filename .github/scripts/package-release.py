#!/usr/bin/env python3
"""Package only the executable, license notices, and build provenance."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[2]
TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-gnu",
)
LICENSE_FILES = (
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "licenses/dawgs-MIT.txt",
    "licenses/BloodHound-Query-Library-MIT.txt",
    "licenses/GraphQLite-MIT.txt",
    "licenses/PCRE2-LICENSE.txt",
    "licenses/SQLite-public-domain.txt",
)
WINDOWS_LICENSE_DIRS = ("libsystre", "libtre", "gettext-runtime", "libiconv")
RUNTIME_MANIFEST = "beagle-runtime-manifest.json"


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(*arguments):
    return subprocess.check_output(arguments, cwd=ROOT, text=True).strip()


def build_inputs():
    """Verify the tracked public inputs before recording release provenance."""
    inputs = json.loads((ROOT / "vendor/build-inputs.json").read_text(encoding="utf-8"))
    for relative, expected in inputs["files"].items():
        if sha256(ROOT / relative) != expected:
            raise ValueError(f"tracked public build input checksum mismatch: {relative}")
    return inputs


def native_build_metadata():
    """Select this build's OUT_DIR from Cargo output, never a stale glob match."""
    package_id = command("cargo", "pkgid", "--locked")
    messages = ROOT / "build/release-cargo.json"
    out_dirs = set()
    for line in messages.read_text(encoding="utf-8").splitlines():
        message = json.loads(line)
        if message.get("reason") == "build-script-executed" and message.get("package_id") == package_id:
            out_dirs.add(message["out_dir"])
    if len(out_dirs) != 1:
        raise ValueError("release Cargo output must identify exactly one Beagle native build")
    metadata_path = Path(out_dirs.pop()) / "graphqlite-build.json"
    return json.loads(metadata_path.read_text(encoding="utf-8"))


def release_version(tag):
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    version = manifest["package"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version):
        raise ValueError(f"unsupported Cargo version: {version!r}")
    if tag != f"v{version}":
        raise ValueError(f"release tag must be v{version}, received {tag!r}")
    return version


def archive_name(version, target):
    suffix = ".zip" if target.endswith("windows-gnu") else ".tar.gz"
    return f"beagle-{version}-{target}{suffix}"


def pinned_toolchain():
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
    version = toolchain["toolchain"]["channel"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("release Rust toolchain must be pinned to an exact version")
    return version


def helper_protocol(executable, version, commit, target):
    info = json.loads(command(str(executable), "--build-info"))
    expected = {
        "name": "beagle", "version": version, "protocol": 1,
        "beagleRevision": commit, "target": target,
    }
    if info != expected:
        raise ValueError("executable build info does not match the release source/target")
    probe = subprocess.run(
        [str(executable), "helper-stdio"],
        input='{"id":1,"command":{"type":"shutdown"}}\n',
        capture_output=True, text=True, timeout=30, check=True,
    )
    messages = [json.loads(line) for line in probe.stdout.splitlines()]
    if len(messages) != 2:
        raise ValueError("helper did not return exactly ready and shutdown messages")
    ready, shutdown = messages
    if (ready.get("type"), ready.get("name"), ready.get("version"), ready.get("protocol")) != (
        "ready", "beagle", version, 1
    ) or not {"open", "query", "catalog", "shutdown"}.issubset(ready.get("operations", [])):
        raise ValueError("helper ready message does not match the desktop protocol")
    if shutdown != {"type": "response", "id": 1, "ok": True, "value": None}:
        raise ValueError("helper did not shut down cleanly")
    return ready


def source_archive_name(version):
    return f"beagle-{version}-windows-dependency-sources.tar.gz"


def tar_archive(staging, archive, epoch):
    def normalize(member):
        member.uid = member.gid = 0
        member.uname = member.gname = ""
        member.mtime = epoch
        member.mode = 0o755 if member.isdir() or member.name.endswith("/beagle") else 0o644
        return member

    with archive.open("wb") as destination:
        with gzip.GzipFile(fileobj=destination, mode="wb", filename="", mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as bundle:
                bundle.add(staging, arcname=staging.name, filter=normalize)


def windows_sources(version, commit, epoch):
    manifest_path = ROOT / ".github/build/windows-posix.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    archive = ROOT / "dist" / source_archive_name(version)
    with tempfile.TemporaryDirectory(prefix="beagle-windows-sources-") as temporary:
        staging = Path(temporary) / f"beagle-{version}-windows-dependency-sources"
        staging.mkdir()
        shutil.copyfile(manifest_path, staging / "windows-posix.json")
        for package in manifest["packages"]:
            filename = package["source_url"].rsplit("/", 1)[1]
            source = ROOT / "build/windows-sources" / filename
            if sha256(source) != package["source_sha256"]:
                raise ValueError(f"Windows source package checksum mismatch: {filename}")
            shutil.copyfile(source, staging / filename)
        instructions = f"""# Windows dependency sources for Beagle {version}

These are the complete, pinned MSYS2 source packages used for libsystre,
TRE, GNU gettext's libintl, and GNU libiconv in this Windows executable.
Each package includes its upstream source and MSYS2 build recipe. The
adjacent windows-posix.json records source and binary package checksums.

Beagle source: tag v{version}, commit {commit} in the same repository as
this GitHub release. Download the release's Source code archive or check
out that exact tag. It includes Cargo.lock, Rust source, the native build
integration, public query catalogs, and checksum-pinned GraphQLite sources.

To rebuild Beagle against these libraries or your modified versions:

1. Install Rust {pinned_toolchain()} with the x86_64-pc-windows-gnu target and an MSYS2
   MINGW64 toolchain (gcc, bison, and flex). To rebuild the dependency
   packages themselves, also install MSYS2's base-devel, tar, and zstd.
2. Extract the desired .src.tar.zst package in MSYS2. Its PKGBUILD and
   source archives are the inputs to makepkg-mingw. Apply your changes,
   then use MINGW_ARCH=mingw64 makepkg-mingw --syncdeps --cleanbuild in
   that package directory. Extract the resulting packages into a chosen
   prefix, preserving their mingw64/include and mingw64/lib layout.
3. Set BEAGLE_WINDOWS_POSIX_ROOT to the absolute path of the rebuilt
   mingw64 prefix, then run:
       cargo build --locked --release --target x86_64-pc-windows-gnu
   The prefix must contain regex.h and static libsystre.a, libtre.a,
   libintl.a, and libiconv.a. Ensure the MSYS2 compiler and build tools
   are on PATH. The executable is target/x86_64-pc-windows-gnu/release/beagle.exe.

Cargo normally downloads and verifies the original binary packages.
The BEAGLE_WINDOWS_POSIX_ROOT override selects your own prefix directly.
Beagle compilation does not require Python, PyYAML, angreal, or Make.
The source package license texts describe each component's terms.
"""
        (staging / "REBUILD.md").write_text(instructions, encoding="utf-8")
        tar_archive(staging, archive, epoch)
    print(archive)


def package(version, tag, target):
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    executable_name = "beagle.exe" if target.endswith("windows-gnu") else "beagle"
    executable = target_dir / target / "release" / executable_name
    executable = executable.resolve()
    if command(str(executable), "--version") != f"beagle {version}":
        raise ValueError("built executable version does not match the release tag")
    if command("git", "status", "--porcelain"):
        raise ValueError("release packaging requires a clean source checkout")
    commit = command("git", "rev-parse", "HEAD")
    rust_toolchain = pinned_toolchain()
    rustc = command("rustc", "--version", "--verbose")
    if rustc.split()[1] != rust_toolchain:
        raise ValueError("active Rust compiler does not match rust-toolchain.toml")
    ready = helper_protocol(executable, version, commit, target)
    inputs = build_inputs()
    native = native_build_metadata()
    provenance = {
        "schema_version": 1,
        "project": "beagle",
        "version": version,
        "tag": tag,
        "commit": commit,
        "tree": command("git", "rev-parse", "HEAD^{tree}"),
        "target": target,
        "rustc": rustc,
        "rust_toolchain": rust_toolchain,
        "helper_protocol": ready["protocol"],
        "helper_operations": ready["operations"],
        "cargo_lock_sha256": sha256(ROOT / "Cargo.lock"),
        "binary": {"name": executable_name, "sha256": sha256(executable)},
        "build_inputs": inputs,
        "native_build": native,
    }
    if os.environ.get("GITHUB_RUN_ID"):
        repository = os.environ["GITHUB_REPOSITORY"]
        run_id = os.environ["GITHUB_RUN_ID"]
        provenance["github_actions"] = {
            "repository": repository,
            "run_id": run_id,
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
            "run_url": f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{repository}/actions/runs/{run_id}",
        }

    output = ROOT / "dist"
    output.mkdir(exist_ok=True)
    archive = output / archive_name(version, target)
    epoch = int(command("git", "show", "-s", "--format=%ct", "HEAD"))
    with tempfile.TemporaryDirectory(prefix="beagle-release-") as temporary:
        staging = Path(temporary) / f"beagle-{version}-{target}"
        staging.mkdir()
        shutil.copy2(executable, staging / executable_name)
        (staging / executable_name).chmod(0o755)
        for relative in LICENSE_FILES:
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        if target.endswith("windows-gnu"):
            prefix = Path(native["windows_posix_prefix"])
            for name in WINDOWS_LICENSE_DIRS:
                source = prefix / "share/licenses" / name
                if not source.is_dir():
                    raise ValueError(f"missing Windows dependency license directory: {source}")
                shutil.copytree(source, staging / "licenses/windows-posix" / name)
            provenance["windows_dependencies"] = json.loads(
                (ROOT / ".github/build/windows-posix.json").read_text(encoding="utf-8")
            )
        (staging / "BUILD-PROVENANCE.json").write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if target.endswith("windows-gnu"):
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                for path in sorted(staging.rglob("*")):
                    if path.is_file():
                        bundle.write(path, path.relative_to(staging.parent).as_posix())
        else:
            tar_archive(staging, archive, epoch)
    print(archive)
    if target.endswith("windows-gnu"):
        windows_sources(version, provenance["commit"], epoch)


def runtime_archive_record(archive, version, target):
    root = f"beagle-{version}-{target}"
    executable = "beagle.exe" if target.endswith("windows-gnu") else "beagle"
    if target.endswith("windows-gnu"):
        with zipfile.ZipFile(archive) as bundle:
            provenance = json.loads(bundle.read(f"{root}/BUILD-PROVENANCE.json"))
            binary_sha256 = hashlib.sha256(bundle.read(f"{root}/{executable}")).hexdigest()
    else:
        with tarfile.open(archive, "r:gz") as bundle:
            provenance = json.load(bundle.extractfile(f"{root}/BUILD-PROVENANCE.json"))
            binary_sha256 = hashlib.file_digest(bundle.extractfile(f"{root}/{executable}"), "sha256").hexdigest()
    if provenance.get("target") != target or provenance.get("binary") != {
        "name": executable, "sha256": binary_sha256
    }:
        raise ValueError(f"release binary provenance mismatch: {target}")
    return provenance, {
        "archive": {"name": archive.name, "sha256": sha256(archive)},
        "root": root,
        "binary": provenance["binary"],
    }


def checksums(version):
    output = ROOT / "dist"
    expected = {archive_name(version, target) for target in TARGETS}
    expected.add(source_archive_name(version))
    actual = {path.name for path in output.iterdir()}
    if actual != expected:
        raise ValueError(f"release archive set mismatch: missing={expected - actual}, unexpected={actual - expected}")
    manifest = {
        "schema_version": 1,
        "project": "beagle",
        "version": version,
        "tag": f"v{version}",
        "commit": command("git", "rev-parse", "HEAD"),
        "tree": command("git", "rev-parse", "HEAD^{tree}"),
        "rust_toolchain": pinned_toolchain(),
        "helper_protocol": 1,
        "cargo_lock_sha256": sha256(ROOT / "Cargo.lock"),
    }
    targets = {}
    for target in TARGETS:
        provenance, record = runtime_archive_record(output / archive_name(version, target), version, target)
        if any(provenance.get(key) != value for key, value in manifest.items()):
            raise ValueError(f"release archive source identity mismatch: {target}")
        targets[target] = record
    manifest["targets"] = targets
    (output / RUNTIME_MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    expected.add(RUNTIME_MANIFEST)
    checksum_file = output / "SHA256SUMS"
    checksum_file.write_text(
        "".join(f"{sha256(output / name)}  {name}\n" for name in sorted(expected)),
        encoding="utf-8",
    )
    print(checksum_file.read_text(encoding="utf-8"), end="")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate-tag", "package", "checksums"):
        subcommand = commands.add_parser(name)
        subcommand.add_argument("--tag", required=True)
        if name == "package":
            subcommand.add_argument("--target", required=True, choices=TARGETS)
    args = parser.parse_args()
    version = release_version(args.tag)
    if args.command == "validate-tag":
        print(f"version={version}")
        print(f"prerelease={str('-' in version.split('+')[0]).lower()}")
    elif args.command == "package":
        package(version, args.tag, args.target)
    else:
        checksums(version)


if __name__ == "__main__":
    main()
