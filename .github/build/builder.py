#!/usr/bin/env python3
"""Build the pinned GraphQLite source through its required angreal workflow."""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import venv

ROOT = pathlib.Path(__file__).resolve().parents[2]


def run(command, **kwargs):
    subprocess.run([str(item) for item in command], check=True, **kwargs)


def checksum(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract_verified(archive, destination, inventory):
    """Extract regular, inventoried files only; also supports Python 3.11."""
    seen = set()
    with tarfile.open(archive) as archive_file:
        for member in archive_file:
            relative = pathlib.PurePosixPath(member.name)
            if (not member.isfile() or relative.is_absolute() or ".." in relative.parts
                    or relative.parts[0] != "graphqlite"):
                raise RuntimeError("unexpected GraphQLite archive member: " + member.name)
            name = str(relative.relative_to("graphqlite"))
            if name not in inventory or name in seen:
                raise RuntimeError("uninventoried GraphQLite archive member: " + member.name)
            data = archive_file.extractfile(member).read()
            if hashlib.sha256(data).hexdigest() != inventory[name]:
                raise RuntimeError("GraphQLite archive file checksum mismatch: " + name)
            output = destination.joinpath(*relative.parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
            seen.add(name)
    if seen != set(inventory):
        raise RuntimeError("GraphQLite archive is missing inventoried files")


def pinned_source(build, *, clean=False):
    archive = ROOT / "vendor/graphqlite-source.tar.gz"
    manifest = json.loads((ROOT / "vendor/graphqlite-source.json").read_text())
    digest = checksum(archive)
    if digest != manifest["source_archive_sha256"]:
        raise RuntimeError("GraphQLite source archive checksum mismatch")
    destination = build / ("backend-" + digest[:16])
    source = destination / "graphqlite"
    if clean and destination.exists():
        shutil.rmtree(destination)
    if not source.exists():
        destination.mkdir(parents=True, exist_ok=True)
        extract_verified(archive, destination, manifest["files"])
    for relative, expected in manifest["files"].items():
        if checksum(source / relative) != expected:
            raise RuntimeError("GraphQLite source file changed: " + relative)
    return source, manifest


def angreal_executable(build, supplied, *, versioned=False):
    if supplied:
        return supplied.resolve()
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    environment = build / ("backend-python-" + version if versioned else "backend-python")
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    angreal = environment / ("Scripts/angreal.exe" if os.name == "nt" else "bin/angreal")
    if python.exists():
        existing = subprocess.run(
            [str(python), "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"],
            text=True, capture_output=True, check=False,
        )
        if existing.returncode or existing.stdout.strip() != version:
            shutil.rmtree(environment)
    if not python.exists():
        venv.create(environment, with_pip=True)
    if not angreal.exists():
        run([python, "-m", "pip", "install", "angreal==2.9.2"])
    return angreal


def build_environment():
    environment = os.environ.copy()
    if sys.platform == "darwin":
        for directory in ("/opt/homebrew/opt/bison/bin", "/usr/local/opt/bison/bin"):
            if pathlib.Path(directory).exists():
                environment["PATH"] = directory + os.pathsep + environment["PATH"]
                break
    for command in ("make", "bison", "flex"):
        executable = environment.get(command.upper(), command)
        if not shutil.which(executable, path=environment["PATH"]):
            raise RuntimeError(command + " is required to build GraphQLite")
    return environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=pathlib.Path,
                        help="use a local corrected source checkout for extension diagnostics")
    parser.add_argument("--angreal", type=pathlib.Path,
                        help="use an already installed angreal (offline builds)")
    parser.add_argument("--static", action="store_true", help="build Cargo's static archive")
    parser.add_argument("--out-dir", type=pathlib.Path, help="Cargo output directory (static mode)")
    parser.add_argument("--sqlite-include", type=pathlib.Path,
                        help="headers from Cargo's bundled libsqlite3-sys (static mode)")
    args = parser.parse_args()
    if not (3, 11) <= sys.version_info[:2] <= (3, 14):
        parser.error("Python 3.11 through 3.14 is required by the pinned angreal helper; set BEAGLE_PYTHON for Cargo builds")
    if args.static and (args.source or not args.out_dir or not args.sqlite_include):
        parser.error("--static requires --out-dir and --sqlite-include, and forbids --source")
    build = args.out_dir.resolve() if args.static else ROOT / "build"
    build.mkdir(parents=True, exist_ok=True)
    environment = build_environment()
    if args.source:
        source, manifest = args.source.resolve(), None
    else:
        # Cargo reruns this only after relevant build inputs change. A fresh
        # extraction prevents old generated parsers/objects or unlisted sources
        # from contaminating a new static build.
        source, manifest = pinned_source(build, clean=args.static)
    angreal = angreal_executable(build, args.angreal, versioned=args.static)
    if args.static:
        sqlite_include = args.sqlite_include.resolve()
        for filename in ("sqlite3.h", "sqlite3ext.h"):
            if not (sqlite_include / filename).is_file():
                raise RuntimeError("missing bundled SQLite header: " + filename)
        for name in ("BEAGLE_CC", "BEAGLE_AR"):
            if not environment.get(name):
                raise RuntimeError(name + " must be supplied by Cargo build.rs")
        integration = ROOT / ".github/build"
        shutil.copy2(integration / "Makefile.beagle", source / "Makefile.beagle")
        shutil.copy2(integration / "task_beagle_static.py", source / ".angreal/task_beagle_static.py")
        environment["BEAGLE_SQLITE_INCLUDE"] = str(sqlite_include)
        run([angreal, "beagle-static"], cwd=source, env=environment)
        destination = build / "libbeagle_graphqlite.a"
        shutil.copy2(source / "build/libbeagle_graphqlite.a", destination)
        metadata = {
            "archive": str(destination),
            "sha256": checksum(destination),
            "source_commit": manifest["base_commit"],
            "source_archive_sha256": manifest["source_archive_sha256"],
            "sqlite_header_sha256": checksum(sqlite_include / "sqlite3.h"),
            "compiler": json.loads(environment["BEAGLE_CC"]),
        }
        (build / "graphqlite-build.json").write_text(json.dumps(metadata, indent=2) + "\n")
    else:
        run([angreal, "build", "extension", "--release"], cwd=source, env=environment)
        suffix = ".dll" if os.name == "nt" else ".dylib" if sys.platform == "darwin" else ".so"
        extension = source / "build" / ("graphqlite" + suffix)
        if not extension.exists():
            raise RuntimeError("angreal did not produce the platform GraphQLite extension: " + str(extension))
        destination = build / extension.name
        shutil.copy2(extension, destination)
        metadata = {"extension": str(destination), "sha256": checksum(destination)}
    print(json.dumps(metadata))


if __name__ == "__main__":
    main()
