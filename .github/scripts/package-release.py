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


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(*arguments):
    return subprocess.check_output(arguments, cwd=ROOT, text=True).strip()


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
integration, and the checksum-pinned public-input bootstrap.

To rebuild Beagle against these libraries or your modified versions:

1. Install Rust stable with the x86_64-pc-windows-gnu target, Python 3.13,
   and an MSYS2 MINGW64 toolchain (gcc, make, bison, flex, tar, and zstd).
   Install Python build helpers: PyYAML==6.0.3 and angreal==2.9.2.
2. Extract the desired .src.tar.zst package in MSYS2. Its PKGBUILD and
   source archives are the inputs to makepkg-mingw. Apply your changes,
   then use MINGW_ARCH=mingw64 makepkg-mingw --syncdeps --cleanbuild in
   that package directory. Extract the resulting packages into a chosen
   prefix, preserving their mingw64/include and mingw64/lib layout.
3. In the Beagle source directory, run:
       python .github/scripts/prepare-build.py
   This restores public GraphQLite sources and query definitions. Set
   BEAGLE_PYTHON to your Python executable and BEAGLE_ANGREAL to angreal.
4. Set BEAGLE_WINDOWS_POSIX_ROOT to the absolute path of the rebuilt
   mingw64 prefix, then run:
       cargo build --locked --release --target x86_64-pc-windows-gnu
   The prefix must contain regex.h and static libsystre.a, libtre.a,
   libintl.a, and libiconv.a. Ensure the MSYS2 compiler and build tools
   are on PATH. The executable is target/x86_64-pc-windows-gnu/release/beagle.exe.

The normal prepare_windows_posix.py helper verifies the original binary
packages. Skip that helper when linking your modified libraries: the
BEAGLE_WINDOWS_POSIX_ROOT override selects your own prefix directly.
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
    inputs = json.loads((ROOT / "build/ci-inputs.json").read_text(encoding="utf-8"))
    provenance = {
        "schema_version": 1,
        "project": "beagle",
        "version": version,
        "tag": tag,
        "commit": command("git", "rev-parse", "HEAD"),
        "target": target,
        "rustc": command("rustc", "--version", "--verbose"),
        "cargo_lock_sha256": sha256(ROOT / "Cargo.lock"),
        "binary": {"name": executable_name, "sha256": sha256(executable)},
        "build_inputs": inputs,
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
            prefix = Path(os.environ["BEAGLE_WINDOWS_POSIX_ROOT"])
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


def checksums(version):
    output = ROOT / "dist"
    expected = {archive_name(version, target) for target in TARGETS}
    expected.add(source_archive_name(version))
    actual = {path.name for path in output.iterdir()}
    if actual != expected:
        raise ValueError(f"release archive set mismatch: missing={expected - actual}, unexpected={actual - expected}")
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
