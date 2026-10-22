#!/usr/bin/env python3
"""Prepare the exact MSYS2 static libraries pinned for Beagle's Windows target."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]


def checksum(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_download(package, cache, offline=False):
    filename = package['url'].rsplit('/', 1)[1]
    if not filename or filename != Path(filename).name:
        raise RuntimeError('Invalid pinned package filename')
    archive = cache / filename
    if not archive.exists():
        if offline:
            raise RuntimeError('Missing cached package for offline setup: ' + filename)
        cache.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=cache, delete=False) as downloaded:
                temporary = Path(downloaded.name)
                with urllib.request.urlopen(package['url'], timeout=60) as response:
                    shutil.copyfileobj(response, downloaded)
            if checksum(temporary) != package['sha256']:
                raise RuntimeError('Downloaded package checksum mismatch: ' + filename)
            temporary.replace(archive)
        except BaseException:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            raise
    if checksum(archive) != package['sha256']:
        raise RuntimeError('Cached package checksum mismatch: ' + filename)
    return archive


def verify_archives(prefix, packages):
    for package in packages:
        for filename, expected in package['static_archive_sha256'].items():
            if checksum(prefix / 'lib' / filename) != expected:
                raise RuntimeError('Static archive checksum mismatch: ' + filename)


def prepare_sources(output, *, cache=None, offline=False,
                    manifest_path=ROOT / '.github/build/windows-posix.json'):
    """Retain the exact source packages corresponding to the pinned binaries."""
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    cache = (cache or output).resolve()
    manifest = json.loads(manifest_path.read_text())
    manifest_sha256 = checksum(manifest_path)
    marker = output / 'windows-posix-sources.json'
    if marker.exists() and json.loads(marker.read_text())['manifest_sha256'] != manifest_sha256:
        raise RuntimeError('Pinned source packages changed; choose a fresh --output')
    packages = []
    for package in manifest['packages']:
        archive = checked_download({
            'url': package['source_url'],
            'sha256': package['source_sha256'],
        }, cache, offline)
        # Inspect the checksum-verified archive without extracting it. Use a
        # relative name because MSYS tar interprets C: paths as remote hosts.
        listing = subprocess.check_output(
            ['tar', '-tf', archive.name], cwd=archive.parent, text=True,
        ).splitlines()
        for name in listing:
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts:
                raise RuntimeError('Unsafe pinned source member: ' + name)
        if not set(package['source_members']).issubset(listing):
            raise RuntimeError('Source package lacks its pinned build recipe or source: ' + archive.name)
        destination = output / archive.name
        if destination.exists():
            if destination.is_symlink() or checksum(destination) != package['source_sha256']:
                raise RuntimeError('Existing source package differs; left untouched: ' + str(destination))
        elif archive != destination:
            shutil.copy2(archive, destination)
        packages.append({
            'name': package['name'],
            'version': package['version'],
            'archive': archive.name,
            'source_url': package['source_url'],
            'source_sha256': package['source_sha256'],
            'source_members': package['source_members'],
            'binary_url': package['url'],
            'binary_sha256': package['sha256'],
        })
    report = {
        'target': manifest['target'],
        'manifest_sha256': manifest_sha256,
        'packages': packages,
    }
    content = json.dumps(report, indent=2) + '\n'
    if marker.exists():
        if marker.read_text() != content:
            raise RuntimeError('Source provenance differs; left untouched: ' + str(marker))
    else:
        marker.write_text(content)
    return report


def prepare(output, *, cache=None, offline=False, manifest_path=ROOT / '.github/build/windows-posix.json'):
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    cache = (cache or output / 'packages').resolve()
    manifest = json.loads(manifest_path.read_text())
    prefix = output / 'mingw64'
    marker = output / 'windows-posix-build.json'
    if prefix.exists():
        if not marker.is_file():
            raise RuntimeError('Output already contains an unmanaged mingw64 directory; choose a fresh --output')
        previous = json.loads(marker.read_text())
        if previous['manifest_sha256'] != checksum(manifest_path):
            raise RuntimeError('Pinned packages changed; choose a fresh --output')
        actual = {str(path.relative_to(prefix)): checksum(path) for path in prefix.rglob('*') if path.is_file()}
        if actual != previous['files']:
            raise RuntimeError('Prepared Windows POSIX files changed; choose a fresh --output')
        verify_archives(prefix, manifest['packages'])
        return previous
    archives = [checked_download(package, cache, offline) for package in manifest['packages']]
    with tempfile.TemporaryDirectory(prefix='extract-', dir=output) as directory:
        staging = Path(directory)
        for archive in archives:
            # Only relative paths reach tar; MSYS tar otherwise treats C: paths
            # as remote archive locations when invoked by native Windows Python.
            local = staging / archive.name
            shutil.copy2(archive, local)
            listing = subprocess.check_output(['tar', '-tf', local.name], cwd=staging, text=True)
            selected = []
            for name in listing.splitlines():
                path = PurePosixPath(name)
                if path.is_absolute() or '..' in path.parts:
                    raise RuntimeError('Unsafe pinned package member: ' + name)
                if path.parts and path.parts[0] == 'mingw64':
                    selected.append(name)
            if not selected:
                raise RuntimeError('Pinned package has no mingw64 contents: ' + archive.name)
            subprocess.run(['tar', '-xf', local.name, 'mingw64'], cwd=staging, check=True)
            local.unlink()
        verify_archives(staging / 'mingw64', manifest['packages'])
        (staging / 'mingw64').rename(prefix)
    report = {'prefix': str(prefix), 'target': manifest['target'], 'manifest_sha256': checksum(manifest_path),
              'packages': [{'name': item['name'], 'version': item['version'], 'sha256': item['sha256']}
                           for item in manifest['packages']],
              'files': {str(path.relative_to(prefix)): checksum(path) for path in prefix.rglob('*') if path.is_file()}}
    marker.write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/windows-posix')
    parser.add_argument('--cache', type=Path, help='directory containing the four pinned downloaded packages')
    parser.add_argument('--offline', action='store_true', help='require cached packages; never download')
    parser.add_argument('--sources-only', action='store_true',
                        help='retain verified source package archives and provenance instead of preparing binary libraries')
    args = parser.parse_args()
    prepare_inputs = prepare_sources if args.sources_only else prepare
    report = prepare_inputs(args.output, cache=args.cache, offline=args.offline)
    print(json.dumps({key: value for key, value in report.items() if key != 'files'}, indent=2))


if __name__ == '__main__':
    main()
