#!/usr/bin/env python3
"""Maintainer-only refresh of tracked, checksum-pinned public build inputs.

Only public query definitions and native library sources are downloaded. Existing
local inputs are preserved; any difference must be resolved explicitly instead of
silently replacing a maintainer's local files. Normal Cargo builds consume the
tracked inputs directly and do not need this script, Python, or PyYAML.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import urllib.request

import yaml


ROOT = Path(__file__).resolve().parents[2]
GRAPHQLITE_COMMIT = "fce218994355ebd1162b54ed634791864f1bb81d"
QUERY_LIBRARY_COMMIT = "b1fee8f5715f8fb3358e187ca3f1bddbfd125f93"
BLOODHOUND_COMMIT = "1759e1638435595def27eb3ff3c5a6fc32832ddc"
SOURCES = {
    "graphqlite": {
        "url": f"https://codeload.github.com/moloch--/graphqlite/tar.gz/{GRAPHQLITE_COMMIT}",
        "commit": GRAPHQLITE_COMMIT,
        "sha256": "3359a0e3e673a4d37b2ff71778fc3e426b68eee377d1cb1bd5f426601484fdf8",
    },
    "query_library": {
        "url": f"https://codeload.github.com/SpecterOps/BloodHoundQueryLibrary/tar.gz/{QUERY_LIBRARY_COMMIT}",
        "commit": QUERY_LIBRARY_COMMIT,
        "sha256": "0dd37707af08c16c39196a6f6893708cef583e5047b24c74c835645f553702f1",
    },
    "ad_schema": {
        "url": f"https://raw.githubusercontent.com/SpecterOps/BloodHound/{BLOODHOUND_COMMIT}/packages/go/graphschema/ad/ad.go",
        "commit": BLOODHOUND_COMMIT,
        "sha256": "8b7dc8bf88eb19a5dfb2043e199f823e0434cffa47a978e608568b348ce3b51a",
    },
}
EXPECTED_INPUTS = {
    "data/queries.json": "878494e95e4f9474f67a3263f14bd953eca904e8b0ebf7c3040955393214b725",
    "data/ad-attack-paths.json": "a686c67cb0e26873c0231d6a6b2f498cae7258cedd80a61f4f48d0ed2a9362be",
    "vendor/graphqlite-source.tar.gz": "c32942e82cf390ede246be768172230f12557fbf0d5dc3cdb572b1871c00aa07",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def download(source):
    request = urllib.request.Request(source["url"], headers={"User-Agent": "Beagle-build"})
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read()
    if digest(data) != source["sha256"]:
        raise RuntimeError("download checksum mismatch: " + source["url"])
    return data


def archive_files(data, expected_root):
    """Read regular members without extracting upstream paths onto the host."""
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != expected_root:
                raise RuntimeError("unexpected upstream archive path: " + member.name)
            # The original snapshot excludes symlinks and includes regular files.
            if member.isdir() or member.issym():
                continue
            if not member.isfile():
                raise RuntimeError("unexpected upstream archive member: " + member.name)
            name = str(path.relative_to(expected_root))
            if name in files:
                raise RuntimeError("duplicate upstream archive path: " + name)
            files[name] = archive.extractfile(member).read()
    return files


def graphqlite_snapshot(files):
    """Match the existing source-only snapshot, including its file inventory."""
    roots = ("src/", ".angreal/", "vendor/", "bindings/python/vendor/sqlite/", "tests/")
    top_level = {"Makefile", "LICENSE", "CONTRIBUTING.md", "README.md"}
    names = [
        name for name in files
        if name in top_level or (
            name.startswith(roots)
            and "__pycache__" not in PurePosixPath(name).parts
            and PurePosixPath(name).suffix not in {".pyc", ".db"}
        )
    ]
    buffer = io.BytesIO()
    inventory = {}
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(names, key=PurePosixPath):
            data = files[name]
            inventory[name] = digest(data)
            entry = tarfile.TarInfo("graphqlite/" + name)
            entry.size = len(data)
            entry.mode = 0o644
            entry.mtime = 0
            archive.addfile(entry, io.BytesIO(data))
    compressed = io.BytesIO()
    # Explicit level and timestamp reproduce the existing Python 3.15 snapshot
    # on supported Python versions; GzipFile also keeps the OS header portable.
    with gzip.GzipFile(fileobj=compressed, mode="wb", compresslevel=6, mtime=0) as archive:
        archive.write(buffer.getvalue())
    data = compressed.getvalue()
    manifest = {
        "upstream": "https://github.com/moloch--/graphqlite",
        "base_commit": GRAPHQLITE_COMMIT,
        "source_archive_sha256": digest(data),
        "files": inventory,
    }
    return data, json_bytes(manifest)


def query_catalog(files):
    queries = []
    for name in sorted(files):
        if name.startswith("queries/") and name.endswith(".yml"):
            query = yaml.safe_load(files[name])
            if query.get("platforms") == "Active Directory":
                queries.append(query)
    return json_bytes(queries)


def attack_path_kinds(source):
    text = source.decode("utf-8")
    names = dict(re.findall(r'(\w+)\s*=\s*graph.StringKind\("([^"]+)"\)', text))
    match = re.search(
        r"func PathfindingRelationships\(\) \[\]graph.Kind \{\s*return \[\]graph.Kind\{([^}]+)\}",
        text,
    )
    if match is None:
        raise RuntimeError("pinned AD schema has no PathfindingRelationships list")
    return json_bytes([names[name.strip()] for name in match[1].split(",")])


def prepare(root):
    native = archive_files(download(SOURCES["graphqlite"]), "graphqlite-" + GRAPHQLITE_COMMIT)
    queries = archive_files(download(SOURCES["query_library"]), "BloodHoundQueryLibrary-" + QUERY_LIBRARY_COMMIT)
    schema = download(SOURCES["ad_schema"])
    native_archive, native_manifest = graphqlite_snapshot(native)
    sqlite_header = native["bindings/python/vendor/sqlite/sqlite3.h"]
    sqlite_notice = sqlite_header.split(b"*************************************************************************", 1)[0] + b"*/\n"
    outputs = {
        "data/queries.json": query_catalog(queries),
        "data/ad-attack-paths.json": attack_path_kinds(schema),
        "vendor/graphqlite-source.tar.gz": native_archive,
        "vendor/graphqlite-source.json": native_manifest,
        "licenses/BloodHound-Query-Library-MIT.txt": queries["LICENSE"],
        "licenses/GraphQLite-MIT.txt": native["LICENSE"],
        "licenses/PCRE2-LICENSE.txt": native["vendor/pcre2/LICENCE.md"],
        "licenses/SQLite-public-domain.txt": sqlite_notice,
    }
    for name, expected in EXPECTED_INPUTS.items():
        if digest(outputs[name]) != expected:
            raise RuntimeError("generated input checksum mismatch: " + name)
    metadata = {"sources": SOURCES, "files": {name: digest(data) for name, data in outputs.items()}}
    outputs["vendor/build-inputs.json"] = json_bytes(metadata)
    # Check the entire output set before writing any files. Never overwrite local
    # data, source modifications, or a symlink supplied by a maintainer.
    for name, data in outputs.items():
        path = root / name
        if path.is_symlink() or (path.exists() and (not path.is_file() or path.read_bytes() != data)):
            raise RuntimeError("existing local input differs; left untouched: " + str(path))
    for name, data in outputs.items():
        path = root / name
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as output:
                output.write(data)
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root (defaults to this checkout)")
    args = parser.parse_args()
    metadata = prepare(args.root.resolve())
    print(json.dumps({"root": str(args.root.resolve()), "files": metadata["files"]}, indent=2))


if __name__ == "__main__":
    main()
